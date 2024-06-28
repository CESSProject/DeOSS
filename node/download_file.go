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

	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/gin-gonic/gin"
)

func (n *Node) Download_file(c *gin.Context) {
	if _, ok := <-max_concurrent_get_ch; !ok {
		c.JSON(http.StatusTooManyRequests, "server is busy, please try again later.")
		return
	}
	defer func() { max_concurrent_get_ch <- true }()

	var err error
	var size uint64
	fid := c.Param(HTTP_ParameterName_Fid)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" || clientIp == " " {
		clientIp = c.ClientIP()
	}

	n.Logdown("info", clientIp+" download the file: "+fid)

	fpath := filepath.Join(n.GetDirs().FileDir, fid)
	fstat, err := os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			n.Logdown("info", clientIp+" download the file from local: "+fid)
			c.File(fpath)
			return
		}
		os.Remove(fpath)
	}

	fpath, err = n.GetCacheRecord(fid)
	if err == nil {
		fstat, err := os.Stat(fpath)
		if err == nil {
			if fstat.Size() > 0 {
				n.Logdown("info", clientIp+" download the file from cache: "+fid)
				c.File(fpath)
				return
			}
			os.Remove(fpath)
		}
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
		size = order.FileSize.Uint64()
	} else {
		completion = true
		size = fmeta.FileSize.Uint64()
	}

	fpath = filepath.Join(n.GetDirs().FileDir, fid)
	peerList, _ := n.QueryAllOssPeerId(-1)
	for _, v := range peerList {
		addr, err := n.GetPeer(v)
		if err != nil {
			continue
		}
		if n.ID().String() == v {
			continue
		}
		err = n.Connect(context.TODO(), addr)
		if err != nil {
			continue
		}
		err = n.ReadDataAction(addr.ID, fid, fid, fpath, int64(size))
		if err != nil {
			continue
		}
		c.File(fpath)
		err = n.MoveFileToCache(fid, fpath) // add file to cache
		if err != nil {
			n.Logdown("err", clientIp+" add file to cache failed: "+err.Error())
		}
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
	c.File(fpath)
	err = n.MoveFileToCache(fid, fpath) // add file to cache
	if err != nil {
		n.Logdown("err", clientIp+" add file to cache failed: "+err.Error())
	}
}
