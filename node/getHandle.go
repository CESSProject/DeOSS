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

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/sdk-go/core/chain"
	"github.com/CESSProject/sdk-go/core/utils"
	"github.com/gin-gonic/gin"
)

type RtnFileType struct {
	FileSize   uint64
	FileState  string
	UserBriefs []RtnUserBrief
	BlockInfo  []RtnBlockInfo
}

type RtnUserBrief struct {
	User       string
	FileName   string
	BucketName string
}

// file block info
type RtnBlockInfo struct {
	MinerId  uint64
	BlockId  string
	MinerIp  string
	MinerAcc string
}

type SegmentInfo struct {
	SegmentHash  string
	FragmentList []FragmentInfo
}

type FragmentInfo struct {
	FragmentHash string
	Avail        bool
	Miner        string
}

// file meta info
type FileMetaData struct {
	Completion  uint32
	State       string
	SegmentList []SegmentInfo
	Owner       []RtnUserBrief
}

// It is used to authorize users
func (n *Node) GetHandle(c *gin.Context) {
	var (
		clientIp string
		respMsg  = &RespMsg{}
	)
	clientIp = c.ClientIP()
	n.Logs.Query("info", fmt.Sprintf("[%s] %s", clientIp, INFO_PutRequest))

	// verify token
	account, pkey, err := n.VerifyToken(c, respMsg)
	if err != nil {
		n.Logs.Query("err", fmt.Sprintf("[%s] %v", clientIp, err))
		c.JSON(respMsg.Code, respMsg.Err)
		return
	}

	n.Logs.Query("info", fmt.Sprintf("[%s] [%s]", clientIp, account))

	getName := c.Param("name")
	if getName == "version" {
		n.Logs.Query("info", fmt.Sprintf("[%s] Query version", clientIp))
		c.JSON(http.StatusOK, configs.Version)
		return
	}

	if len(getName) != len(chain.FileHash{}) {
		// Query bucket
		if utils.CheckBucketName(getName) {
			n.Logs.Query("info", fmt.Sprintf("[%s] Query bucket [%s] info", clientIp, getName))
			bucketInfo, err := n.Cli.Chain.QueryBucketInfo(pkey, getName)
			if err != nil {
				if err.Error() == chain.ERR_Empty {
					n.Logs.Query("err", fmt.Sprintf("[%s] Query bucket [%s] info: NotFount", clientIp, getName))
					c.JSON(http.StatusNotFound, "NotFound")
					return
				}
				n.Logs.Query("err", fmt.Sprintf("[%s] Query bucket [%s] info: %v", clientIp, getName, err))
				c.JSON(http.StatusInternalServerError, "InternalError")
				return
			}

			filesHash := make([]string, len(bucketInfo.ObjectsList))
			for i := 0; i < len(bucketInfo.ObjectsList); i++ {
				filesHash[i] = string(bucketInfo.ObjectsList[i][:])
			}

			owners := make([]string, len(bucketInfo.Authority))
			for i := 0; i < len(bucketInfo.Authority); i++ {
				owners[i], _ = utils.EncodePublicKeyAsCessAccount(bucketInfo.Authority[i][:])
			}

			data := struct {
				Num    int
				Owners []string
				Files  []string
			}{
				Num:    len(bucketInfo.ObjectsList),
				Owners: owners,
				Files:  filesHash,
			}
			n.Logs.Query("info", fmt.Sprintf("[%s] Query bucket [%s] info suc", clientIp, getName))
			c.JSON(http.StatusOK, data)
			return
		}
		// Query bucket list
		if getName == "*" {
			bucketList, err := n.Cli.Chain.QueryBucketList(pkey)
			if err != nil {
				if err.Error() == chain.ERR_Empty {
					n.Logs.Query("err", fmt.Sprintf("[%s] Query [%s] bucket list: NotFount", clientIp, account))
					c.JSON(http.StatusNotFound, "NotFound")
					return
				}
				n.Logs.Query("err", fmt.Sprintf("[%s] Query [%s] bucket list: %v", clientIp, account, err))
				c.JSON(http.StatusInternalServerError, "InternalError")
				return
			}
			n.Logs.Query("info", fmt.Sprintf("[%s] Query [%s] bucket list suc", clientIp, account))
			c.JSON(http.StatusOK, bucketList)
			return
		}

		n.Logs.Query("err", fmt.Sprintf("[%s] Invalid query para: %s", clientIp, getName))
		c.JSON(http.StatusBadRequest, "InvalidParameter.Name")
		return
	}

	operation := c.Request.Header.Get(configs.Header_Operation)

	// view file
	if operation == "view" {
		n.Logs.Query("info", fmt.Sprintf("[%s] Query file [%s] info", clientIp, getName))
		fmeta, err := n.Cli.Chain.QueryFileMetadata(getName)
		if err != nil {
			if err.Error() == chain.ERR_Empty {
				_, err = n.Cli.QueryStorageOrder(getName)
				if err != nil {
					if err.Error() == chain.ERR_Empty {
						n.Logs.Query("err", fmt.Sprintf("[%s] Query file [%s] info: NotFount", clientIp, getName))
						c.JSON(http.StatusNotFound, "NotFound")
						return
					}
				} else {
					n.Logs.Query("info", fmt.Sprintf("[%s] Query file [%s] info: Data is being stored", clientIp, getName))
					c.JSON(http.StatusOK, "Data is being stored")
					return
				}
				n.Logs.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, getName, err))
				c.JSON(http.StatusInternalServerError, "InternalError")
				return
			}
			n.Logs.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, getName, err))
			c.JSON(http.StatusInternalServerError, "InternalError")
			return
		}

		var fileMetadata FileMetaData
		fileMetadata.Completion = uint32(fmeta.Completion)
		switch int(fmeta.State) {
		case Active:
			fileMetadata.State = "Active"
		case Calculate:
			fileMetadata.State = "Calculate"
		case Missing:
			fileMetadata.State = "Missing"
		case Recovery:
			fileMetadata.State = "Recovery"
		default:
			fileMetadata.State = "Unknown"
		}
		fileMetadata.Owner = make([]RtnUserBrief, len(fmeta.Owner))
		for i := 0; i < len(fmeta.Owner); i++ {
			fileMetadata.Owner[i].BucketName = string(fmeta.Owner[i].BucketName)
			fileMetadata.Owner[i].FileName = string(fmeta.Owner[i].FileName)
			fileMetadata.Owner[i].User, _ = utils.EncodePublicKeyAsCessAccount(fmeta.Owner[i].User[:])
		}
		fileMetadata.SegmentList = make([]SegmentInfo, len(fmeta.SegmentList))
		for i := 0; i < len(fmeta.SegmentList); i++ {
			fileMetadata.SegmentList[i].FragmentList = make([]FragmentInfo, len(fmeta.SegmentList[i].FragmentList))
			fileMetadata.SegmentList[i].SegmentHash = string(fmeta.SegmentList[i].Hash[:])
			for j := 0; j < len(fmeta.SegmentList[i].FragmentList); j++ {
				fileMetadata.SegmentList[i].FragmentList[j].Avail = bool(fmeta.SegmentList[i].FragmentList[j].Avail)
				fileMetadata.SegmentList[i].FragmentList[j].FragmentHash = string(fmeta.SegmentList[i].FragmentList[j].Hash[:])
				fileMetadata.SegmentList[i].FragmentList[j].Miner, _ = utils.EncodePublicKeyAsCessAccount(fmeta.SegmentList[i].FragmentList[j].Miner[:])
			}
		}
		n.Logs.Query("info", fmt.Sprintf("[%s] Query file [%s] info suc", clientIp, getName))
		c.JSON(http.StatusOK, fileMetadata)
		return
	}

	// download file
	if operation == "download" {
		dir := filepath.Join(n.Cli.Workspace(), configs.File)
		n.Logs.Query("info", fmt.Sprintf("[%s] Download file [%s]", clientIp, getName))
		fpath := filepath.Join(dir, getName)
		_, err := os.Stat(fpath)
		if err == nil {
			n.Logs.Query("info", fmt.Sprintf("[%s] Download file [%s] from cache", clientIp, getName))
			c.File(fpath)
			select {
			case <-c.Request.Context().Done():
				return
			}
		}

		// fmeta, err := n.Cli.QueryFile(getName)
		// if err != nil {
		// 	if err.Error() == chain.ERR_Empty {
		// 		n.Logs.Query("err", fmt.Sprintf("[%s] Download file [%s] : NotFount", clientIp, getName))
		// 		c.JSON(http.StatusNotFound, "NotFound")
		// 		return
		// 	}
		// 	n.Logs.Query("err", fmt.Sprintf("[%s] Download file [%s] : %v", clientIp, getName, err))
		// 	c.JSON(http.StatusInternalServerError, "InternalError")
		// 	return
		// }

		//Download from miner
		fpath, err = n.Cli.GetFile(getName, dir)
		if err != nil {
			n.Logs.Query("err", fmt.Sprintf("[%s] Download file [%s] : %v", clientIp, getName, err))
			c.JSON(http.StatusInternalServerError, "InternalError")
			return
		}
		n.Logs.Query("info", fmt.Sprintf("[%s] Download file [%s] suc", clientIp, getName))
		c.File(fpath)
		select {
		case <-c.Request.Context().Done():
			return
		}
	}
	n.Logs.Query("err", fmt.Sprintf("[%s] [%s] InvalidHeader.Operation", clientIp, getName))
	c.JSON(http.StatusBadRequest, "InvalidHeader.Operation")
	return
}
