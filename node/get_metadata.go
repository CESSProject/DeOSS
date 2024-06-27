/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
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

// getHandle
func (n *Node) GetMetadataHandle(c *gin.Context) {
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" || clientIp == " " {
		clientIp = c.ClientIP()
	}

	fid := c.Param(HTTP_ParameterName_Fid)
	n.Query("info", fmt.Sprintf("[%s] get meta data: %s", clientIp, fid))

	var fileMetadata Metadata
	fileMetadata.Fid = fid
	n.Query("info", fmt.Sprintf("[%s] Query file [%s] info", clientIp, fid))
	fmeta, err := n.QueryFile(fid, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, fid, err))
			c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
			return
		}

		dealmap, err := n.QueryDealMap(fid, -1)
		if err != nil {
			if err.Error() != chain.ERR_Empty {
				n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, fid, err))
				c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
				return
			}
			if !n.HasTrackFile(fid) {
				n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: NotFount", clientIp, fid))
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
		n.Query("info", fmt.Sprintf("[%s] Query file [%s] metadata suc", clientIp, fid))
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

	n.Query("info", fmt.Sprintf("[%s] Query file [%s] metadata suc", clientIp, fid))
	c.JSON(http.StatusOK, fileMetadata)
}
