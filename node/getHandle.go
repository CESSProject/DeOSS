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
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	"github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/gin-gonic/gin"
	"github.com/mr-tron/base58"
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

// getHandle
func (n *Node) getHandle(c *gin.Context) {
	var (
		clientIp string
	)

	clientIp = c.ClientIP()
	n.Query("info", fmt.Sprintf("[%s] %s", clientIp, INFO_GetRequest))

	queryName := c.Param(HTTP_ParameterName)
	if queryName == "version" {
		n.Query("info", fmt.Sprintf("[%s] Query version", clientIp))
		c.JSON(http.StatusOK, configs.Version)
		return
	}

	if len(queryName) != len(pattern.FileHash{}) {
		account := c.Request.Header.Get(HTTPHeader_Account)
		if account == "" {
			n.Query("err", fmt.Sprintf("[%s] %s", clientIp, ERR_MissAccount))
			c.JSON(http.StatusBadRequest, ERR_MissAccount)
			return
		}
		pkey, err := utils.ParsingPublickey(account)
		if err != nil {
			n.Query("err", fmt.Sprintf("[%s] %s", clientIp, ERR_InvalidAccount))
			c.JSON(http.StatusBadRequest, ERR_InvalidAccount)
			return
		}
		// Query bucket
		if utils.CheckBucketName(queryName) {
			n.Query("info", fmt.Sprintf("[%s] Query bucket [%s] info", clientIp, queryName))
			bucketInfo, err := n.QueryBucketInfo(pkey, queryName)
			if err != nil {
				if err.Error() == pattern.ERR_Empty {
					n.Query("err", fmt.Sprintf("[%s] Query bucket [%s] info: NotFount", clientIp, queryName))
					c.JSON(http.StatusNotFound, "NotFound")
					return
				}
				n.Query("err", fmt.Sprintf("[%s] Query bucket [%s] info: %v", clientIp, queryName, err))
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
			n.Query("info", fmt.Sprintf("[%s] Query bucket [%s] info suc", clientIp, queryName))
			c.JSON(http.StatusOK, data)
			return
		}
		// Query bucket list
		if queryName == "*" {
			bucketList, err := n.QueryAllBucketName(pkey)
			if err != nil {
				if err.Error() == pattern.ERR_Empty {
					n.Query("err", fmt.Sprintf("[%s] Query [%s] bucket list: NotFount", clientIp, account))
					c.JSON(http.StatusNotFound, "NotFound")
					return
				}
				n.Query("err", fmt.Sprintf("[%s] Query [%s] bucket list: %v", clientIp, account, err))
				c.JSON(http.StatusInternalServerError, "InternalError")
				return
			}
			n.Query("info", fmt.Sprintf("[%s] Query [%s] bucket list suc", clientIp, account))
			c.JSON(http.StatusOK, bucketList)
			return
		}

		n.Query("err", fmt.Sprintf("[%s] Invalid query para: %s", clientIp, queryName))
		c.JSON(http.StatusBadRequest, "InvalidParameter.Name")
		return
	}

	operation := c.Request.Header.Get(configs.Header_Operation)

	// view file
	if operation == "view" {
		n.Query("info", fmt.Sprintf("[%s] Query file [%s] info", clientIp, queryName))
		fmeta, err := n.QueryFileMetadata(queryName)
		if err != nil {
			if err.Error() == pattern.ERR_Empty {
				_, err = n.QueryStorageOrder(queryName)
				if err != nil {
					if err.Error() == pattern.ERR_Empty {
						n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: NotFount", clientIp, queryName))
						c.JSON(http.StatusNotFound, "NotFound")
						return
					}
				} else {
					n.Query("info", fmt.Sprintf("[%s] Query file [%s] info: Data is being stored", clientIp, queryName))
					c.JSON(http.StatusOK, "Data is being stored")
					return
				}
				n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, queryName, err))
				c.JSON(http.StatusInternalServerError, "InternalError")
				return
			}
			n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, queryName, err))
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
		n.Query("info", fmt.Sprintf("[%s] Query file [%s] info suc", clientIp, queryName))
		c.JSON(http.StatusOK, fileMetadata)
		return
	}

	// download file
	if operation == "download" {
		dir := n.GetDirs().FileDir
		n.Query("info", fmt.Sprintf("[%s] Download file [%s]", clientIp, queryName))
		fpath := filepath.Join(dir, queryName)
		_, err := os.Stat(fpath)
		if err == nil {
			n.Query("info", fmt.Sprintf("[%s] Download file [%s] from cache", clientIp, queryName))
			c.File(fpath)
			select {
			case <-c.Request.Context().Done():
				return
			}
		}

		//Download from miner
		fpath, err = n.fetchFiles(queryName, dir)
		if err != nil {
			n.Query("err", fmt.Sprintf("[%s] Download file [%s] : %v", clientIp, queryName, err))
			c.JSON(http.StatusInternalServerError, "InternalError")
			return
		}
		n.Query("info", fmt.Sprintf("[%s] Download file [%s] suc", clientIp, queryName))
		c.File(fpath)
		select {
		case <-c.Request.Context().Done():
			return
		}
	}
	n.Query("err", fmt.Sprintf("[%s] [%s] InvalidHeader.Operation", clientIp, queryName))
	c.JSON(http.StatusBadRequest, "InvalidHeader.Operation")
	return
}

func (n *Node) fetchFiles(roothash, dir string) (string, error) {
	var (
		acc          string
		segmentspath = make([]string, 0)
	)
	userfile := filepath.Join(dir, roothash)
	_, err := os.Stat(userfile)
	if err == nil {
		return userfile, nil
	}
	os.MkdirAll(dir, pattern.DirMode)
	f, err := os.Create(userfile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmeta, err := n.QueryFileMetadata(roothash)
	if err != nil {
		return "", err
	}

	for _, v := range fmeta.Owner {
		acc, err = utils.EncodePublicKeyAsCessAccount(v.User[:])
		if err != nil {
			continue
		}
		_, err = os.Stat(filepath.Join(n.GetDirs().FileDir, acc, roothash, roothash))
		if err == nil {
			return filepath.Join(n.GetDirs().FileDir, acc, roothash, roothash), nil
		}
	}

	defer func(basedir string) {
		for _, segment := range fmeta.SegmentList {
			os.Remove(filepath.Join(basedir, string(segment.Hash[:])))
			for _, fragment := range segment.FragmentList {
				os.Remove(filepath.Join(basedir, string(fragment.Hash[:])))
			}
		}
	}(dir)

	for _, segment := range fmeta.SegmentList {
		fragmentpaths := make([]string, 0)
		for _, fragment := range segment.FragmentList {
			miner, err := n.QueryStorageMiner(fragment.Miner[:])
			if err != nil {
				return "", err
			}
			peerid := base58.Encode([]byte(string(miner.PeerId[:])))
			addr, ok := n.GetPeer(peerid)
			if !ok {
				addr, err = n.DHTFindPeer(peerid)
				if err != nil {
					continue
				}
			}
			err = n.Connect(n.GetRootCtx(), addr)
			if err != nil {
				continue
			}
			fragmentpath := filepath.Join(dir, string(fragment.Hash[:]))
			err = n.ReadFileAction(addr.ID, roothash, string(fragment.Hash[:]), fragmentpath, pattern.FragmentSize)
			if err != nil {
				continue
			}
			fragmentpaths = append(fragmentpaths, fragmentpath)
			segmentpath := filepath.Join(dir, string(segment.Hash[:]))
			if len(fragmentpaths) >= pattern.DataShards {
				err = n.RedundancyRecovery(segmentpath, fragmentpaths)
				if err != nil {
					return "", err
				}
				segmentspath = append(segmentspath, segmentpath)
				break
			}
		}
	}

	if len(segmentspath) != len(fmeta.SegmentList) {
		return "", fmt.Errorf("Download failed")
	}
	var writecount = 0
	for i := 0; i < len(fmeta.SegmentList); i++ {
		for j := 0; j < len(segmentspath); j++ {
			if string(fmeta.SegmentList[i].Hash[:]) == filepath.Base(segmentspath[j]) {
				buf, err := os.ReadFile(segmentspath[j])
				if err != nil {
					return "", err
				}
				if (writecount + 1) >= len(fmeta.SegmentList) {
					f.Write(buf[:(fmeta.FileSize.Uint64() - uint64(writecount*pattern.SegmentSize))])
				} else {
					f.Write(buf)
				}
				writecount++

				break
			}
		}
	}
	if writecount != len(fmeta.SegmentList) {
		return "", fmt.Errorf("Write failed")
	}

	return userfile, nil
}
