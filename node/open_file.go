/*
Copyright (C) CESS. All rights reserved.
Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
)

func (n *Node) Preview_file(c *gin.Context) {
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

	n.Logopen("info", clientIp+" will open the file: "+fid)

	var ok bool
	var size uint64
	var completion bool
	var fext string
	var fname string
	var contenttype interface{}
	fmeta, err := n.QueryFile(fid, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			n.Logopen("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, fid, err))
			c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
			return
		}
		order, err := n.QueryDealMap(fid, -1)
		if err != nil {
			if err.Error() != chain.ERR_Empty {
				n.Logopen("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, fid, err))
				c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
				return
			}
			n.Logopen("err", fmt.Sprintf("[%s] Query file [%s] info: Not found", clientIp, fid))
			c.JSON(http.StatusNotFound, ERR_NotFound)
			return
		}
		size = order.FileSize.Uint64()
		fname = string(order.User.FileName)
		temp := strings.Split(string(order.User.FileName), ".")
		if len(temp) < 2 {
			contenttype = "application/octet-stream"
		} else {
			fext = "." + temp[len(temp)-1]
			contenttype, ok = contentType.Load(strings.ToLower(fext))
			if !ok {
				contenttype = "application/octet-stream"
			}
		}
	} else {
		completion = true
		size = fmeta.FileSize.Uint64()
		for i := 0; i < len(fmeta.Owner); i++ {
			fname = string(fmeta.Owner[i].FileName)
			fext = filepath.Ext(fname)
			contenttype, ok = contentType.Load(strings.ToLower(fext))
			if !ok {
				contenttype = "application/octet-stream"
			}
		}
	}

	n.Logopen("info", clientIp+" file name: "+fname)

	fpath := filepath.Join(n.GetDirs().FileDir, fid)
	n.Logopen("info", clientIp+" fpath: "+fpath)
	fstat, err := os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from local", clientIp, fid))
			c.Header("Content-length", fmt.Sprintf("%d", fstat.Size()))
			switch strings.ToLower(fext) {
			case ".mp4", ".mov", ".avi", ".asf", ".asx", ".rm", ".rmvb", ".3gp", ".m4v", ".wmv", ".mkv", ".flv", ".f4v", ".vob", ".mpeg",
				".wav", ".flac", ".ape", ".alac", ".wv", ".mp3", ".aac", ".wma", ".mp2", ".ra", ".midi", ".cda", ".m4a":
				VideoAndAudioHeader(c, fname, fstat.Sys().(*syscall.Stat_t).Mtim.Sec)
			case "application/octet-stream":
				c.FileAttachment(fpath, fname)
				return
			default:
				filemd5, _ := sutils.CalcMD5(fpath)
				OtherHeader(c, fname, hex.EncodeToString(filemd5), fstat.Sys().(*syscall.Stat_t).Mtim.Sec)
			}
			content, err := os.ReadFile(fpath)
			if err != nil {
				c.JSON(500, "try again later")
				return
			}
			c.Data(200, contenttype.(string), content)
			return
		} else {
			os.Remove(fpath)
		}
	}

	fpath, err = n.GetCacheRecord(fid) //query file from cache
	if err != nil {
		n.Logopen("err", fmt.Sprintf("[%s] The file [%s] was not found in the cache: %v", clientIp, fid, err))
	}

	fstat, err = os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from cache", clientIp, fid))
			c.Header("Content-length", fmt.Sprintf("%d", fstat.Size()))
			switch strings.ToLower(fext) {
			case ".mp4", ".mov", ".avi", ".asf", ".asx", ".rm", ".rmvb", ".3gp", ".m4v", ".wmv", ".mkv", ".flv", ".f4v", ".vob", ".mpeg",
				".wav", ".flac", ".ape", ".alac", ".wv", ".mp3", ".aac", ".wma", ".mp2", ".ra", ".midi", ".cda", ".m4a":
				VideoAndAudioHeader(c, fname, fstat.Sys().(*syscall.Stat_t).Mtim.Sec)
			case "application/octet-stream":
				c.FileAttachment(fpath, fname)
				return
			default:
				filemd5, _ := sutils.CalcMD5(fpath)
				OtherHeader(c, fname, hex.EncodeToString(filemd5), fstat.Sys().(*syscall.Stat_t).Mtim.Sec)
			}
			content, err := os.ReadFile(fpath)
			if err != nil {
				c.JSON(500, "try again later")
				return
			}
			c.Data(200, contenttype.(string), content)
			return
		} else {
			os.Remove(fpath)
		}
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
		err = n.MoveFileToCache(fid, fpath) // add file to cache
		if err != nil {
			n.Logopen("err", fmt.Sprintf("[%s] add file [%s] to cache error [%v]", clientIp, fid, err))
		}
		break
	}

	fstat, err = os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from cache", clientIp, fid))
			c.Header("Content-length", fmt.Sprintf("%d", fstat.Size()))
			switch strings.ToLower(fext) {
			case ".mp4", ".mov", ".avi", ".asf", ".asx", ".rm", ".rmvb", ".3gp", ".m4v", ".wmv", ".mkv", ".flv", ".f4v", ".vob", ".mpeg",
				".wav", ".flac", ".ape", ".alac", ".wv", ".mp3", ".aac", ".wma", ".mp2", ".ra", ".midi", ".cda", ".m4a":
				VideoAndAudioHeader(c, fname, fstat.Sys().(*syscall.Stat_t).Mtim.Sec)
			case "application/octet-stream":
				c.FileAttachment(fpath, fname)
				return
			default:
				filemd5, _ := sutils.CalcMD5(fpath)
				OtherHeader(c, fname, hex.EncodeToString(filemd5), fstat.Sys().(*syscall.Stat_t).Mtim.Sec)
			}
			content, err := os.ReadFile(fpath)
			if err != nil {
				c.JSON(500, "try again later")
				return
			}
			c.Data(200, contenttype.(string), content)
			return
		} else {
			os.Remove(fpath)
		}
	}

	if !completion {
		n.Logopen("err", fmt.Sprintf("[%s] download file [%s] : %v", clientIp, fid, "The file is being stored, please download it from the gateway where you uploaded it."))
		c.JSON(http.StatusNotFound, "The file is being stored, please download it from the gateway where you uploaded it.")
		return
	}

	// download from miner
	fpath, err = n.fetchFiles(fid, n.GetDirs().FileDir, cipher)
	if err != nil {
		n.Logopen("err", fmt.Sprintf("[%s] Download file [%s] : %v", clientIp, fid, err))
		c.JSON(http.StatusInternalServerError, "File download failed, please try again later.")
		return
	}
	n.Logopen("info", fmt.Sprintf("[%s] Download file [%s] suc", clientIp, fid))
	fstat, err = os.Stat(fpath)
	if err == nil {
		if fstat.Size() > 0 {
			err = n.MoveFileToCache(fid, fpath) // add file to cache
			if err != nil {
				n.Logopen("err", fmt.Sprintf("[%s] add file [%s] to cache error [%v]", clientIp, fid, err))
			}
			n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from cache", clientIp, fid))
			c.Header("Content-length", fmt.Sprintf("%d", fstat.Size()))
			switch strings.ToLower(fext) {
			case ".mp4", ".mov", ".avi", ".asf", ".asx", ".rm", ".rmvb", ".3gp", ".m4v", ".wmv", ".mkv", ".flv", ".f4v", ".vob", ".mpeg",
				".wav", ".flac", ".ape", ".alac", ".wv", ".mp3", ".aac", ".wma", ".mp2", ".ra", ".midi", ".cda", ".m4a":
				VideoAndAudioHeader(c, fname, fstat.Sys().(*syscall.Stat_t).Mtim.Sec)
			case "application/octet-stream":
				c.FileAttachment(fpath, fname)
				return
			default:
				filemd5, _ := sutils.CalcMD5(fpath)
				OtherHeader(c, fname, hex.EncodeToString(filemd5), fstat.Sys().(*syscall.Stat_t).Mtim.Sec)
			}
			content, err := os.ReadFile(fpath)
			if err != nil {
				c.JSON(http.StatusInternalServerError, "try again later")
				return
			}
			c.Data(200, contenttype.(string), content)
			return
		} else {
			os.Remove(fpath)
		}
	}
	c.JSON(http.StatusInternalServerError, "File download failed, please try again later.")
}

func VideoAndAudioHeader(c *gin.Context, fname string, mtime int64) {
	c.Header("Accept-ranges", "bytes")
	c.Writer.Header().Add("Access-control-allow-headers", "Content-Type")
	c.Writer.Header().Add("Access-control-allow-headers", "Range")
	c.Writer.Header().Add("Access-control-allow-headers", "User-Agent")
	c.Writer.Header().Add("Access-control-allow-headers", "X-Request-With")
	c.Header("Accept-control-allow-methods", "GET")
	c.Header("Accept-control-allow-origin", "*")
	c.Writer.Header().Add("Accept-control-expose-headers", "Content-Range")
	c.Writer.Header().Add("Accept-control-expose-headers", "X-Chunked-Output")
	c.Writer.Header().Add("Accept-control-expose-headers", "X-Stream-Output")
	c.Header("Cache-control", "public, max-age=29030400, immutable")
	c.Header("Content-disposition", fmt.Sprintf("inline; filename=%v", fname))
	c.Header("last-modified", time.Unix(mtime, 0).Format("2006-01-02 15:04:05"))
}

func OtherHeader(c *gin.Context, fname, md5 string, mtime int64) {
	c.Header("Accept-ranges", "bytes")
	c.Header("Accept-control-allow-origin", "*")
	c.Header("Cache-control", "public, max-age=2592000, no-transform, immutable")
	c.Header("Content-disposition", fmt.Sprintf("inline; filename=%v", fname))
	c.Header("content-md5", md5)
	c.Header("last-modified", time.Unix(mtime, 0).Format("2006-01-02 15:04:05"))
}
