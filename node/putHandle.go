/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/sdk-go/core/client"
	"github.com/gin-gonic/gin"
)

type FileStoreInfo struct {
	FileId      string         `json:"file_id"`
	FileState   string         `json:"file_state"`
	Scheduler   string         `json:"scheduler"`
	FileSize    int64          `json:"file_size"`
	IsUpload    bool           `json:"is_upload"`
	IsCheck     bool           `json:"is_check"`
	IsShard     bool           `json:"is_shard"`
	IsScheduler bool           `json:"is_scheduler"`
	Miners      map[int]string `json:"miners,omitempty"`
}

type RecordInfo struct {
	SegmentInfo []client.SegmentInfo `json:"segmentInfo"`
	Owner       []byte               `json:"owner"`
	Roothash    string               `json:"roothash"`
	Filename    string               `json:"filename"`
	Buckname    string               `json:"buckname"`
}

// It is used to authorize users
func (n *Node) putHandle(c *gin.Context) {
	var (
		err      error
		clientIp string
		account  string
		filesize int64
		fpath    string
		filehash string
		roothash string
		httpCode int
		respMsg  = &RespMsg{}
	)

	clientIp = c.ClientIP()
	n.Logs.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, INFO_PutRequest))

	// verify token
	account = n.VerifyToken(c, respMsg)

	// get owner's public key
	pkey, err := utils.DecodePublicKeyOfCessAccount(account)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusBadRequest, ERR_InvalidToken)
		return
	}

	// get parameter name
	putName := c.Param(PUT_ParameterName)
	if putName == "" {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidName))
		c.JSON(http.StatusBadRequest, ERR_InvalidName)
		return
	}

	// bucket name
	bucketName := c.Request.Header.Get(Header_BucketName)

	if bucketName == "" {
		if c.Request.ContentLength > 0 {
			n.Logs.Upfile("err", fmt.Sprintf("[%v] %s", c.ClientIP(), ERR_EmptyBucketName))
			c.JSON(http.StatusBadRequest, ERR_EmptyBucketName)
			return
		}
		txHash, err := n.Cli.CreateBucket(pkey, putName)
		if err != nil {
			n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", c.ClientIP(), err))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
		return
	}

	// upload file operation
	// verify bucket name
	if !n.Cli.CheckBucketName(bucketName) {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidBucketName))
		c.JSON(http.StatusBadRequest, ERR_InvalidBucketName)
		return
	}

	content_length := c.Request.ContentLength
	if content_length <= 0 {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_EmptyFile))
		c.JSON(400, "InvalidParameter.EmptyFile")
		return
	}

	filesize, filehash, fpath, httpCode, err = n.SaveFormFile(c, account, putName)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		filesize, filehash, fpath, httpCode, err = n.SaveBody(c, account, putName)
		if err != nil {
			n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(httpCode, err)
			return
		}
	}

	filesize = filesize
	filehash = filehash
	segmentInfo, roothash, err := n.Cli.ProcessingData(fpath)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	var recordInfo = &RecordInfo{
		SegmentInfo: segmentInfo,
		Owner:       pkey,
		Roothash:    roothash,
		Filename:    putName,
		Buckname:    bucketName,
	}

	f, err := os.Create(filepath.Join(n.TrackDir, roothash))
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	b, err := json.Marshal(recordInfo)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	f.Write(b)
	err = f.Sync()
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, roothash)
	return
}

func (n *Node) TrackFile() {
	var (
		count      uint8
		roothash   string
		recordFile RecordInfo
		//linuxFileAttr *syscall.Stat_t
	)
	for {
		time.Sleep(time.Second * 10)
		count++

		files, _ := filepath.Glob(filepath.Join(n.TrackDir, "*"))
		for i := 0; i < len(files); i++ {
			roothash = filepath.Base(files[i])
			b, err := os.ReadFile(files[i])
			if err != nil {
				n.Logs.Upfile("info", fmt.Sprintf("[%s] File backup failed: %v", roothash, err))
				os.Remove(files[i])
				continue
			}

			err = json.Unmarshal(b, &recordFile)
			if err != nil {
				n.Logs.Upfile("info", fmt.Sprintf("[%s] File backup failed: %v", roothash, err))
				os.Remove(files[i])
				continue
			}

			if roothash != recordFile.Roothash {
				n.Logs.Upfile("info", fmt.Sprintf("[%s] File backup failed: fid is not equal", roothash))
				os.Remove(files[i])
				continue
			}

			roothash, err = n.Cli.PutFile(recordFile.Owner, recordFile.SegmentInfo, roothash, recordFile.Filename, recordFile.Buckname)
			if err != nil {
				n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
				continue
			}
		}

		// if count > 60 {
		// 	count = 0
		// 	files, _ = filepath.Glob(filepath.Join(n.FileDir, "*"))
		// 	if len(files) > 0 {
		// 		for _, v := range files {
		// 			fs, err := os.Stat(filepath.Join(n.FileDir, v))
		// 			if err == nil {
		// 				linuxFileAttr = fs.Sys().(*syscall.Stat_t)
		// 				if time.Since(time.Unix(linuxFileAttr.Atim.Sec, 0)).Hours() > configs.FileCacheExpirationTime {
		// 					os.Remove(filepath.Join(n.FileDir, v))
		// 				}
		// 			}
		// 		}
		// 	}
		// }
	}
}
