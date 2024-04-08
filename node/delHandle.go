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
	sutils "github.com/CESSProject/cess-go-sdk/utils"
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
	)

	clientIp = c.Request.Header.Get("X-Forwarded-For")
	n.Del("info", fmt.Sprintf("[%v] %v", clientIp, INFO_DelRequest))
	// verify the authorization
	account := c.Request.Header.Get(HTTPHeader_Account)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)
	pkey, err := n.VerifyAccountSignature(account, message, signature)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
		c.JSON(http.StatusBadRequest, err.Error())
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
}

// delHandle is used to delete buckets or files
func (n *Node) delFilesHandle(c *gin.Context) {
	var (
		err      error
		txHash   string
		clientIp string
		pkey     []byte
	)

	clientIp = c.Request.Header.Get("X-Forwarded-For")
	n.Del("info", fmt.Sprintf("[%v] %v", clientIp, INFO_DelRequest))

	account := c.Request.Header.Get(HTTPHeader_Account)
	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)

	if err = n.AccessControl(account); err != nil {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusForbidden, err.Error())
		return
	}

	if ethAccount != "" {
		ethAccInSian, err := VerifyEthSign(message, signature)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		if ethAccInSian != ethAccount {
			n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, "ETH signature verification failed"))
			c.JSON(http.StatusBadRequest, "ETH signature verification failed")
			return
		}
		pkey, err = sutils.ParsingPublickey(account)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, fmt.Sprintf("invalid cess account: %s", account))
			return
		}
	} else {
		pkey, err = n.VerifyAccountSignature(account, message, signature)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
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
		c.JSON(400, fmt.Sprintf("[%v] empty files", clientIp))
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
