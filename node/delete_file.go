/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"net/http"

	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/gin-gonic/gin"
)

// delHandle is used to delete buckets or files
func (n *Node) Delete_file(c *gin.Context) {
	if !checkDeOSSStatus(n, c) {
		return
	}

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}
	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)
	account := c.Request.Header.Get(HTTPHeader_Account)
	fid := c.Param(HTTP_ParameterName)
	n.Logdel("info", utils.StringBuilder(400, clientIp, account, ethAccount, fid, message, signature))

	pkey, err := n.VerifyAccountSignature(account, message, signature)
	if err != nil {
		n.Logdel("err", clientIp+" VerifyAccountSignature: "+err.Error())
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	blockHash, err := n.DeleteFile(pkey, fid)
	if err != nil {
		n.Logdel("err", clientIp+" DeleteFile failed: "+err.Error())
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	n.Logdel("info", clientIp+" DeleteFile suc: "+blockHash)
	n.Delete([]byte("transfer:" + fid))
	c.JSON(200, map[string]string{"block hash": blockHash})
}
