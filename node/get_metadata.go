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

// file meta info
type Metadata struct {
	Fid   string         `json:"fid"`
	Size  uint64         `json:"size"`
	Owner []RtnUserBrief `json:"owner"`
}

type RtnUserBrief struct {
	User       string `json:"user"`
	FileName   string `json:"file_name"`
	BucketName string `json:"bucket_name"`
}

func (n *Node) Get_metadata(c *gin.Context) {
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	fid := c.Param(HTTP_ParameterName_Fid)
	n.Logget("info", clientIp+" get metadata of the file: "+fid)

	var fileMetadata Metadata
	fileMetadata.Fid = fid
	fmeta, err := n.QueryFile(fid, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			n.Logget("err", clientIp+" QueryFile failed: "+err.Error())
			c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
			return
		}

		dealmap, err := n.QueryDealMap(fid, -1)
		if err != nil {
			if err.Error() != chain.ERR_Empty {
				n.Logget("err", clientIp+" QueryDealMap failed: "+err.Error())
				c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
				return
			}
			if !n.HasTrackFile(fid) {
				n.Logget("err", clientIp+" not found the file: "+fid)
				c.JSON(http.StatusNotFound, "NotFound")
				return
			}
		}
		user, _ := sutils.EncodePublicKeyAsCessAccount(dealmap.User.User[:])
		fileMetadata.Size = dealmap.FileSize.Uint64()
		fileMetadata.Owner = append(fileMetadata.Owner, RtnUserBrief{
			User:       user,
			FileName:   string(dealmap.User.FileName),
			BucketName: string(dealmap.User.BucketName),
		})
		n.Logget("info", clientIp+" get metadata from dealmap suc of the file: "+fid)
		c.JSON(http.StatusOK, fileMetadata)
		return
	}

	fileMetadata.Size = fmeta.FileSize.Uint64()
	fileMetadata.Owner = make([]RtnUserBrief, len(fmeta.Owner))
	for i := 0; i < len(fmeta.Owner); i++ {
		fileMetadata.Owner[i].BucketName = string(fmeta.Owner[i].BucketName)
		fileMetadata.Owner[i].FileName = string(fmeta.Owner[i].FileName)
		fileMetadata.Owner[i].User, _ = sutils.EncodePublicKeyAsCessAccount(fmeta.Owner[i].User[:])
	}
	n.Logget("info", clientIp+" get metadata from file suc of the file: "+fid)
	c.JSON(http.StatusOK, fileMetadata)
}
