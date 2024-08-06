/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"net/http"

	"github.com/CESSProject/DeOSS/common/utils"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
)

func (n *Node) Delete_bucket(c *gin.Context) {
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
	bucketName := c.Param(HTTP_ParameterName)
	n.Logdel("info", utils.StringBuilder(400, clientIp, account, ethAccount, bucketName, message, signature))

	pkey, err := n.VerifyAccountSignature(account, message, signature)
	if err != nil {
		n.Logdel("err", clientIp+" VerifyAccountSignature: "+err.Error())
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	if !sutils.CheckBucketName(bucketName) {
		n.Logput("err", clientIp+" CheckBucketName: "+bucketName)
		c.JSON(http.StatusBadRequest, "invalid bucket")
		return
	}

	blockHash, err := n.DeleteBucket(pkey, bucketName)
	if err != nil {
		n.Logdel("err", clientIp+" DeleteBucket failed: "+err.Error())
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	n.Logdel("info", clientIp+" DeleteBucket suc: "+blockHash)
	c.JSON(http.StatusOK, map[string]string{"block hash": blockHash})
}
