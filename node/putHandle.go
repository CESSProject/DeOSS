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
	"strconv"

	"github.com/CESSProject/sdk-go/core/pattern"
	sutils "github.com/CESSProject/sdk-go/core/utils"
	"github.com/gin-gonic/gin"
)

type RecordInfo struct {
	SegmentInfo []pattern.SegmentDataInfo `json:"segmentInfo"`
	Owner       []byte                    `json:"owner"`
	Roothash    string                    `json:"roothash"`
	Filename    string                    `json:"filename"`
	Buckname    string                    `json:"buckname"`
	Putflag     bool                      `json:"putflag"`
	Count       uint8                     `json:"count"`
}

// It is used to authorize users
func (n *Node) putHandle(c *gin.Context) {
	var (
		err      error
		clientIp string
		account  string
		fpath    string
		roothash string
		httpCode int
		pkey     []byte
		respMsg  = &RespMsg{}
	)

	clientIp = c.ClientIP()
	n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, INFO_PutRequest))

	// verify token
	account, pkey, err = n.VerifyToken(c, respMsg)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(respMsg.Code, respMsg.Err)
		return
	}

	// get parameter name
	putName := c.Param(PUT_ParameterName)
	if putName == "" {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidName))
		c.JSON(http.StatusBadRequest, ERR_InvalidName)
		return
	}

	// bucket name
	bucketName := c.Request.Header.Get(Header_BucketName)

	if bucketName == "" {
		if c.Request.ContentLength > 0 {
			n.Upfile("err", fmt.Sprintf("[%v] %s", c.ClientIP(), ERR_EmptyBucketName))
			c.JSON(http.StatusBadRequest, ERR_EmptyBucketName)
			return
		}
		if !sutils.CheckBucketName(putName) {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidBucketName))
			c.JSON(http.StatusBadRequest, ERR_InvalidBucketName)
			return
		}
		txHash, err := n.CreateBucket(pkey, putName)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %v", c.ClientIP(), err))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
		return
	}

	// upload file operation
	// verify bucket name
	if !sutils.CheckBucketName(bucketName) {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidBucketName))
		c.JSON(http.StatusBadRequest, ERR_InvalidBucketName)
		return
	}

	content_length := c.Request.ContentLength
	if content_length <= 0 {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_EmptyFile))
		c.JSON(http.StatusBadRequest, ERR_EmptyFile)
		return
	}

	fpath, httpCode, err = n.SaveFormFile(c, account, putName)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		fpath, httpCode, err = n.SaveBody(c, account, putName)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(httpCode, err)
			return
		}
	}
	defer os.Remove(fpath)

	fstat, err := os.Stat(fpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	userInfo, err := n.QueryUserSpaceSt(pkey)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	blockheight, err := n.QueryBlockHeight("")
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	if userInfo.Deadline <= blockheight {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_SpaceExpired))
		c.JSON(http.StatusForbidden, ERR_SpaceExpired)
		return
	}

	usedSpace := fstat.Size() * 15 / 10
	remainingSpace, err := strconv.ParseUint(userInfo.RemainingSpace, 10, 64)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	if usedSpace > int64(remainingSpace) {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_NotEnoughSpace))
		c.JSON(http.StatusForbidden, ERR_NotEnoughSpace)
		return
	}

	segmentInfo, roothash, err := n.ProcessingData(fpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	roothashpath := filepath.Join(n.GetDirs().FileDir, roothash)
	_, err = os.Stat(roothashpath)
	if err == nil {
		_, err = os.Stat(filepath.Join(n.TrackDir, roothash))
		if err == nil {
			c.JSON(http.StatusOK, roothash)
			return
		}
	}

	err = os.Rename(fpath, roothashpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	var recordInfo = &RecordInfo{
		SegmentInfo: segmentInfo,
		Owner:       pkey,
		Roothash:    roothash,
		Filename:    putName,
		Buckname:    bucketName,
		Putflag:     false,
	}

	f, err := os.Create(filepath.Join(n.TrackDir, roothash))
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	b, err := json.Marshal(recordInfo)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	f.Write(b)
	err = f.Sync()
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, roothash)
	return
}
