/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"net/http"

	"github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
)

func (n *Node) Get_bucket(c *gin.Context) {
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}
	account := c.Request.Header.Get(HTTPHeader_Account)
	bucketName := c.Request.Header.Get(HTTPHeader_Bucket)
	if bucketName == "" {
		n.Logget("info", clientIp+" get bucket list: "+account)
	} else {
		n.Logget("info", clientIp+" get bucket info: "+account+" "+bucketName)
	}

	err := n.AccessControl(account)
	if err != nil {
		n.Logget("info", clientIp+" AccessControl: "+err.Error())
		c.JSON(http.StatusForbidden, err.Error())
		return
	}

	pkey, err := sutils.ParsingPublickey(account)
	if err != nil {
		n.Logget("info", clientIp+" ParsingPublickey: "+err.Error())
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	if bucketName != "" {
		if !sutils.CheckBucketName(bucketName) {
			n.Logget("err", clientIp+" CheckBucketName: "+err.Error())
			c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
			return
		}
		bucketInfo, err := n.QueryBucket(pkey, bucketName, -1)
		if err != nil {
			if err.Error() == chain.ERR_Empty {
				n.Logget("err", clientIp+" get bucket info: NotFount")
				c.JSON(http.StatusNotFound, "NotFound")
				return
			}
			n.Logget("err", clientIp+" get bucket info failed: "+err.Error())
			c.JSON(http.StatusInternalServerError, "InternalError")
			return
		}

		filesHash := make([]string, len(bucketInfo.FileList))
		for i := 0; i < len(bucketInfo.FileList); i++ {
			filesHash[i] = string(bucketInfo.FileList[i][:])
		}

		owners := make([]string, len(bucketInfo.Authority))
		for i := 0; i < len(bucketInfo.Authority); i++ {
			owners[i], _ = sutils.EncodePublicKeyAsCessAccount(bucketInfo.Authority[i][:])
		}

		data := struct {
			Num    int
			Owners []string
			Files  []string
		}{
			Num:    len(bucketInfo.FileList),
			Owners: owners,
			Files:  filesHash,
		}
		n.Logget("info", clientIp+" get bucket info suc: "+account+" "+bucketName)
		c.JSON(http.StatusOK, data)
		return
	}

	// get bucket list
	bucketList, err := n.QueryAllBucketName(pkey, -1)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			n.Logget("err", clientIp+" get bucket list: NotFount")
			c.JSON(http.StatusNotFound, "NotFound")
			return
		}
		n.Logget("err", clientIp+" get bucket list failed: "+err.Error())
		c.JSON(http.StatusInternalServerError, "InternalError")
		return
	}
	n.Logget("info", clientIp+" get bucket list suc: "+account)
	c.JSON(http.StatusOK, bucketList)
}
