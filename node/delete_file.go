/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

// import (
// 	"errors"
// 	"net/http"
// 	"os"
// 	"path/filepath"

// 	"github.com/CESSProject/DeOSS/common/utils"
// 	"github.com/CESSProject/cess-go-sdk/chain"
// 	"github.com/gin-gonic/gin"
// )

// // delHandle is used to delete buckets or files
// func (n *Node) DeleteFile(c *gin.Context) {
// 	if !checkDeOSSStatus(n, c) {
// 		return
// 	}

// 	clientIp := c.Request.Header.Get("X-Forwarded-For")
// 	if clientIp == "" {
// 		clientIp = c.ClientIP()
// 	}

// 	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)
// 	message := c.Request.Header.Get(HTTPHeader_Message)
// 	signature := c.Request.Header.Get(HTTPHeader_Signature)
// 	account := c.Request.Header.Get(HTTPHeader_Account)
// 	fid := c.Param(HTTP_ParameterName)
// 	n.Logdel("info", utils.StringBuilder(400, clientIp, account, ethAccount, fid, message, signature))

// 	pkey, code, err := verifySignature(n, account, ethAccount, message, signature)
// 	if err != nil {
// 		n.Logput("err", clientIp+" verifySignature: "+err.Error())
// 		c.JSON(code, err.Error())
// 		return
// 	}

// 	blockHash, err := n.ChainClient.DeleteFile(pkey, fid)
// 	if err != nil {
// 		n.Logdel("err", clientIp+" DeleteFile failed: "+err.Error())
// 		c.JSON(http.StatusBadRequest, err.Error())
// 		return
// 	}
// 	n.RemoveCacheRecord(fid)

// 	n.Logdel("info", clientIp+" DeleteFile suc: "+blockHash)
// 	c.JSON(200, map[string]string{"block hash": blockHash})

// 	_, err = n.QueryFile(fid, -1)
// 	if err != nil {
// 		if errors.Is(err, chain.ERR_RPC_EMPTY_VALUE) {
// 			data, err := n.ParseTrackFile(fid)
// 			if err == nil {
// 				for _, segment := range data.Segment {
// 					for _, fragment := range segment.FragmentHash {
// 						os.Remove(fragment)
// 					}
// 				}
// 			}
// 			os.Remove(filepath.Join(n.fileDir, fid))
// 		}
// 	}
// }
