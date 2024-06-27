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
	"github.com/gin-gonic/gin"
)

func (n *Node) DownloadFileHandle(c *gin.Context) {
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

	n.Query("info", fmt.Sprintf("[%s] will download the file: %s", clientIp, fid))

	//fpath := utils.FindFile(n.GetDirs().FileDir, queryName)
	fpath, err := n.GetCacheRecord(fid) //query file from cache
	if err == nil {
		fstat, err := os.Stat(fpath)
		if err == nil {
			if fstat.Size() > 0 {
				n.Query("info", fmt.Sprintf("[%s] Download file [%s] from cache", clientIp, fid))
				c.File(fpath)
				return
			} else {
				os.Remove(fpath)
			}
		}
	}

	var completion bool
	fmeta, err := n.QueryFile(fid, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, fid, err))
			c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
			return
		}
		order, err := n.QueryDealMap(fid, -1)
		if err != nil {
			if err.Error() != chain.ERR_Empty {
				n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, fid, err))
				c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
				return
			}
			n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: Not found", clientIp, fid))
			c.JSON(http.StatusNotFound, ERR_NotFound)
			return
		} else {
			size = order.FileSize.Uint64()
		}
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
			n.Query("err", fmt.Sprintf("[%s] add file [%s] to cache error [%v]", clientIp, fid, err))
		}
		return
	}

	if !completion {
		n.Query("err", fmt.Sprintf("[%s] download file [%s] : %v", clientIp, fid, "The file is being stored, please download it from the gateway where you uploaded it."))
		c.JSON(http.StatusNotFound, "The file is being stored, please download it from the gateway where you uploaded it.")
		return
	}

	// download from miner
	fpath, err = n.fetchFiles(fid, n.GetDirs().FileDir, cipher)
	if err != nil {
		n.Query("err", fmt.Sprintf("[%s] Download file [%s] : %v", clientIp, fid, err))
		c.JSON(http.StatusInternalServerError, "File download failed, please try again later.")
		return
	}
	n.Query("info", fmt.Sprintf("[%s] Download file [%s] suc", clientIp, fid))
	c.File(fpath)
	err = n.MoveFileToCache(fid, fpath) // add file to cache
	if err != nil {
		n.Query("err", fmt.Sprintf("[%s] add file [%s] to cache error [%v]", clientIp, fid, err))
	}
}
