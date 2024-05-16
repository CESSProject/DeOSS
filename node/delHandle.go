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

	"github.com/CESSProject/cess-go-sdk/chain"
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

	if n.GetBalances() <= 1 {
		c.JSON(http.StatusInternalServerError, "service balance is insufficient, please try again later.")
		return
	}

	if !n.GetRpcState() {
		c.JSON(http.StatusInternalServerError, "service rpc connection failed, please try again later.")
		return
	}

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

	if len(deleteName) == chain.FileHashLen {
		txHash, err = n.DeleteFile(pkey, deleteName)
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
