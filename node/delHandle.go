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
	FileId []string `json:"file_id"`
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
	account, pkey, err = n.VerifyToken(c, respMsg)
	if err != nil {
		n.Del("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(respMsg.Code, respMsg.Err)
		return
	}
	n.Del("info", fmt.Sprintf("[%v] %v", clientIp, account))

	deleteName := c.Param(PUT_ParameterName)
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
		os.Remove(filepath.Join(n.TrackDir, deleteName))
		n.Delete([]byte("transfer:" + deleteName))
		c.JSON(200, txHash)
	} else if sutils.CheckBucketName(deleteName) {
		txHash, err = n.DeleteBucket(pkey, deleteName)
		if err != nil {
			n.Del("err", fmt.Sprintf("[%v] [DeleteBucket] %v", clientIp, err))
			c.JSON(400, err.Error())
			return
		}
		n.Del("info", fmt.Sprintf("[%v] [DeleteBucket] %v", clientIp, txHash))
		c.JSON(200, txHash)
	} else {
		deleteNames := c.PostFormArray("delete_list")
		if err != nil {
			n.Del("err", fmt.Sprintf("[%v] [PostFormArray] %v", clientIp, err))
			c.JSON(400, "InvalidBody.DeleteList")
			return
		}
		n.Del("info", fmt.Sprintf("[%v] [PostFormArray] %v", clientIp, deleteNames))
		txHash, failList, err := n.DeleteFile(pkey, deleteNames)
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
}
