/*
Copyright (C) CESS. All rights reserved.
Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/erasure"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
)

const max_concurrent_get = 30

var max_concurrent_get_ch chan bool

func init() {
	max_concurrent_get_ch = make(chan bool, max_concurrent_get)
	for i := 0; i < max_concurrent_get; i++ {
		max_concurrent_get_ch <- true
	}
}

func (n *Node) Download_file(c *gin.Context) {
	if _, ok := <-max_concurrent_get_ch; !ok {
		c.JSON(http.StatusTooManyRequests, "server is busy, please try again later.")
		return
	}
	defer func() { max_concurrent_get_ch <- true }()

	fid := c.Param(HTTP_ParameterName_Fid)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	n.Logdown("info", clientIp+" download the file: "+fid)

	size, fpath, err := n.CheckLocalFile(fid)
	if err == nil {
		f, err := os.Open(fpath)
		if err != nil {
			n.Logdown("info", clientIp+" download the file from local, open file failed: "+err.Error())
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		n.Logdown("info", clientIp+" download the file from local: "+fid)
		c.DataFromReader(http.StatusOK, size, "application/octet-stream", f, nil)
		return
	}

	completion := false
	fmeta, err := n.QueryFile(fid, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			n.Logdown("err", clientIp+" QueryFile failed: "+err.Error())
			c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
			return
		}
		order, err := n.QueryDealMap(fid, -1)
		if err != nil {
			if err.Error() != chain.ERR_Empty {
				n.Logdown("err", clientIp+" QueryDealMap failed: "+err.Error())
				c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
				return
			}
			n.Logdown("info", clientIp+" the file is not recorded on the chain: "+fid)
			c.JSON(http.StatusNotFound, ERR_NotFound)
			return
		}
		size = int64(order.FileSize.Uint64())
	} else {
		completion = true
		size = int64(fmeta.FileSize.Uint64())
	}

	fpath = filepath.Join(n.GetDirs().FileDir, fid)
	peerList, _ := n.QueryAllOssPeerId(-1)
	for _, v := range peerList {
		n.Logdown("info", clientIp+" will request to gateway: "+v)
		addr, ok := n.GetPeer(v)
		if !ok {
			n.Logdown("info", clientIp+" request to gateway failed: not found")
			continue
		}
		if n.ID().String() == v {
			n.Logdown("info", clientIp+" request to gateway failed: self-request")
			continue
		}
		err = n.Connect(context.TODO(), addr)
		if err != nil {
			n.Logdown("info", clientIp+" request to gateway to connect failed: "+err.Error())
			continue
		}
		err = n.ReadDataAction(addr.ID, fid, fid, fpath, int64(size))
		if err != nil {
			n.Logdown("info", clientIp+" request to gateway to read file failed: "+err.Error())
			continue
		}
		f, err := os.Open(fpath)
		if err != nil {
			continue
		}
		defer f.Close()
		err = n.MoveFileToCache(fid, fpath) // add file to cache
		if err != nil {
			n.Logdown("err", clientIp+" add file to cache failed: "+err.Error())
		}
		c.DataFromReader(http.StatusOK, int64(size), "application/octet-stream", f, nil)
		return
	}

	if !completion {
		n.Logdown("err", clientIp+" download file failed: the file is being stored, please download it from the gateway where you uploaded it.")
		c.JSON(http.StatusNotFound, "the file is being stored, please download it from the gateway where you uploaded it.")
		return
	}

	// download from miner
	fpath, err = n.fetchFiles(fid, n.GetDirs().FileDir, cipher)
	if err != nil {
		n.Logdown("err", clientIp+" download file failed: "+err.Error())
		c.JSON(http.StatusInternalServerError, "file download failed, please try again later.")
		return
	}
	n.Logdown("info", clientIp+"download the file from miner: "+fid)
	fstat, err := os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			f, err := os.Open(fpath)
			if err == nil {
				defer f.Close()
				n.Logdown("info", clientIp+" download the file from cache: "+fid)
				c.DataFromReader(http.StatusOK, fstat.Size(), "application/octet-stream", f, nil)
				return
			}
		} else {
			os.Remove(fpath)
		}
	}
	n.Logdown("err", clientIp+" download file failed: "+err.Error())
	c.JSON(http.StatusInternalServerError, "file download failed, please try again later.")
	return
}

func (n *Node) fetchFiles(roothash, dir, cipher string) (string, error) {
	userfile := filepath.Join(dir, roothash)
	fstat, err := os.Stat(userfile)
	if err == nil {
		if fstat.Size() > 0 {
			return userfile, nil
		}
	}
	os.MkdirAll(dir, 0755)
	f, err := os.Create(userfile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmeta, err := n.QueryFile(roothash, -1)
	if err != nil {
		return "", err
	}

	defer func(basedir string) {
		for _, segment := range fmeta.SegmentList {
			os.Remove(filepath.Join(basedir, string(segment.Hash[:])))
			for _, fragment := range segment.FragmentList {
				os.Remove(filepath.Join(basedir, string(fragment.Hash[:])))
			}
		}
	}(dir)

	var segmentspath = make([]string, 0)
	fragmentpaths := make([]string, sconfig.DataShards+sconfig.ParShards)

	for _, segment := range fmeta.SegmentList {
		for k, fragment := range segment.FragmentList {
			fragmentpath := filepath.Join(dir, string(fragment.Hash[:]))
			fragmentpaths[k] = fragmentpath
			n.Logdown("info", "will download fragment: "+string(fragment.Hash[:]))
			if string(fragment.Hash[:]) != "080acf35a507ac9849cfcba47dc2ad83e01b75663a516279c8b9d243b719643e" {
				//n.Logdown("info", "connect to "+peerid+" failed: "+err.Error())
				account, _ := sutils.EncodePublicKeyAsCessAccount(fragment.Miner[:])
				n.Logdown("info", "will query the storage miner: "+account)
				miner, err := n.QueryMinerItems(fragment.Miner[:], -1)
				if err != nil {
					n.Logdown("info", "query the storage miner failed: "+err.Error())
					return "", err
				}
				peerid := base58.Encode([]byte(string(miner.PeerId[:])))
				n.Logdown("info", "will connect the peer: "+peerid)
				addr, ok := n.GetPeer(peerid)
				if !ok {
					n.Logdown("info", "not fount the peer: "+peerid)
					continue
				}
				err = n.Connect(context.TODO(), addr)
				if err != nil {
					n.Logdown("info", "connect to "+peerid+" failed: "+err.Error())
					continue
				}
				err = n.ReadFileAction(addr.ID, roothash, string(fragment.Hash[:]), fragmentpath, sconfig.FragmentSize)
				if err != nil {
					n.Logdown("info", " ReadFileAction failed: "+err.Error())
					continue
				}
			} else {
				_, err = os.Stat(fragmentpath)
				if err != nil {
					ff, _ := os.Create(fragmentpath)
					ff.Write(make([]byte, sconfig.FragmentSize))
					ff.Close()
				}
			}
		}
		segmentpath := filepath.Join(dir, string(segment.Hash[:]))
		err = erasure.RSRestore(segmentpath, fragmentpaths)
		if err != nil {
			return "", err
		}
		segmentspath = append(segmentspath, segmentpath)
	}

	if len(segmentspath) != len(fmeta.SegmentList) {
		return "", errors.New("download failed")
	}
	var writecount = 0
	for i := 0; i < len(segmentspath); i++ {
		buf, err := os.ReadFile(segmentspath[i])
		if err != nil {
			fmt.Println("segmentspath not equal fmeta segmentspath")
			os.Exit(0)
		}
		if (writecount + 1) >= len(fmeta.SegmentList) {
			f.Write(buf[:(fmeta.FileSize.Uint64() - uint64(writecount*sconfig.SegmentSize))])
		} else {
			f.Write(buf)
		}
		writecount++
	}
	if writecount != len(fmeta.SegmentList) {
		return "", errors.New("write failed")
	}
	err = f.Sync()
	return userfile, err
}

func (n *Node) CheckLocalFile(fid string) (int64, string, error) {
	fpath := filepath.Join(n.GetDirs().FileDir, fid)
	fstat, err := os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			return fstat.Size(), fpath, nil
		}
		os.Remove(fpath)
	}
	fpath = filepath.Join(n.GetCacheDir(), fid)
	fstat, err = os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			return fstat.Size(), fpath, nil
		}
		os.Remove(fpath)
	}
	return 0, "", errors.New("not fount")
}
