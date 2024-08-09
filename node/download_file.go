/*
Copyright (C) CESS. All rights reserved.
Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/gin-gonic/gin"
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

	fpath = filepath.Join(n.fileDir, fid)
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
		n.Peerstore().AddAddrs(addr.ID, addr.Addrs, time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err = n.ReadDataAction(ctx, addr.ID, fid, fpath)
		if err != nil {
			n.Peerstore().ClearAddrs(addr.ID)
			n.Logdown("info", clientIp+" request to gateway to read file failed: "+err.Error())
			continue
		}
		n.Peerstore().ClearAddrs(addr.ID)
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
	fpath, err = n.retrieve_file(fid, n.fileDir, cipher)
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

func (n *Node) CheckLocalFile(fid string) (int64, string, error) {
	fpath := filepath.Join(n.fileDir, fid)
	n.Logopen("info", " check file: "+fpath)
	fstat, err := os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			return fstat.Size(), fpath, nil
		}
		os.Remove(fpath)
	}
	fpath = filepath.Join(n.GetBasespace(), configs.FILE_CACHE, fid)
	n.Logopen("info", " check file: "+fpath)
	fstat, err = os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			return fstat.Size(), fpath, nil
		}
		os.Remove(fpath)
	}
	n.Logopen("err", " check file failed: no cached")
	return 0, "", errors.New("not fount")
}
