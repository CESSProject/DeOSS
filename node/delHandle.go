/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/gin-gonic/gin"
)

type DelList struct {
	Files []string `json:"files"`
}

// delHandle is used to delete buckets or files
func (n *Node) delHandle(c *gin.Context) {
	var (
		err      error
		txHash   string
		clientIp string
		account  string
		pkey     []byte
		respMsg  = &RespMsg{}
	)

	clientIp = c.ClientIP()
	n.Del("info", fmt.Sprintf("[%v] %v", clientIp, INFO_DelRequest))

	// verify token
	token := c.Request.Header.Get(HTTPHeader_Authorization)
	account, pkey, err = n.verifyToken(token, respMsg)
	if err != nil {
		n.Del("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(respMsg.Code, err.Error())
		return
	}
	n.Del("info", fmt.Sprintf("[%v] %v", clientIp, account))

	deleteName := c.Param(HTTP_ParameterName)
	n.Del("info", fmt.Sprintf("[%v] %v", clientIp, deleteName))

	if len(deleteName) == len(pattern.FileHash{}) {
		txHash, _, err = n.DeleteFile(pkey, []string{deleteName})
		if err != nil {
			n.Del("err", fmt.Sprintf("[%v] [DeleteFile] %v", clientIp, err))
			c.JSON(400, err.Error())
			return
		}
		n.Del("info", fmt.Sprintf("[%v] [DeleteFile] %v", clientIp, txHash))
		os.RemoveAll(filepath.Join(n.GetDirs().FileDir, account, deleteName))
		os.Remove(filepath.Join(n.trackDir, deleteName))
		n.Delete([]byte("transfer:" + deleteName))
		c.JSON(200, txHash)
		return
	}

	if sutils.CheckBucketName(deleteName) {
		txHash, err = n.DeleteBucket(pkey, deleteName)
		if err != nil {
			n.Del("err", fmt.Sprintf("[%v] [DeleteBucket] %v", clientIp, err))
			c.JSON(400, err.Error())
			return
		}
		n.Del("info", fmt.Sprintf("[%v] [DeleteBucket] %v", clientIp, txHash))
		c.JSON(200, txHash)
		return
	}

	n.Del("err", fmt.Sprintf("[%v] invalid parameter: %s", clientIp, deleteName))
	c.JSON(400, fmt.Sprintf("%v or %v", ERR_InvalidFilehash, ERR_InvalidParaBucketName))
	return
}

// delHandle is used to delete buckets or files
func (n *Node) delFilesHandle(c *gin.Context) {
	var (
		err      error
		txHash   string
		clientIp string
		account  string
		pkey     []byte
		respMsg  = &RespMsg{}
	)

	clientIp = c.ClientIP()
	n.Del("info", fmt.Sprintf("[%v] %v", clientIp, INFO_DelRequest))

	// verify token
	token := c.Request.Header.Get(HTTPHeader_Authorization)
	account, pkey, err = n.verifyToken(token, respMsg)
	if err != nil {
		n.Del("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(respMsg.Code, err.Error())
		return
	}

	if !n.AccessControl(account) {
		n.Del("info", fmt.Sprintf("[%v] %v", c.ClientIP(), ERR_Forbidden))
		c.JSON(http.StatusForbidden, ERR_Forbidden)
		return
	}

	n.Del("info", fmt.Sprintf("[%v] %v", clientIp, account))

	var delList DelList
	err = c.ShouldBind(&delList)
	if err != nil {
		n.Del("err", fmt.Sprintf("[%v] [ShouldBind] %v", clientIp, err))
		c.JSON(400, "InvalidBody.DeleteFiles")
		return
	}

	if len(delList.Files) == 0 {
		n.Del("err", fmt.Sprintf("[%v] [ShouldBind] empty files", clientIp))
		c.JSON(400, fmt.Sprintf("empty files"))
		return
	}

	n.Del("info", fmt.Sprintf("[%v] [ShouldBind] %v", clientIp, delList.Files))

	txHash, failList, err := n.DeleteFile(pkey, delList.Files)
	if err != nil {
		n.Del("err", fmt.Sprintf("[%v] [DeleteFile] %v", clientIp, err))
		c.JSON(400, err.Error())
		return
	}

	c.JSON(http.StatusOK, struct {
		Block_hash  string
		Failed_list []pattern.FileHash
	}{Block_hash: txHash, Failed_list: failList})
}
