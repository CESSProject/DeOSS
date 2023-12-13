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
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/core/crypte"
	"github.com/CESSProject/cess-go-sdk/core/erasure"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
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

	clientIp = c.Request.Header.Get("X-Forwarded-For")
	n.Query("info", fmt.Sprintf("[%s] %s", clientIp, INFO_GetRequest))

	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	account := c.Request.Header.Get(HTTPHeader_Account)

	if err := n.AccessControl(account); err != nil {
		n.Query("info", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusForbidden, err.Error())
		return
	}

	queryName := c.Param(HTTP_ParameterName)
	if queryName == "version" {
		n.Query("info", fmt.Sprintf("[%s] Query version", clientIp))
		c.JSON(http.StatusOK, configs.Version)
		return
	}

	if queryName == "peers" {
		n.Query("info", fmt.Sprintf("[%s] Query peers", clientIp))
		_, err := os.Stat(n.peersPath)
		if err != nil {
			buf := n.EncodePeers()
			c.JSON(http.StatusOK, string(buf))
			return
		}
		c.File(n.peersPath)
		return
	}

	if queryName == "file" {
		fid := c.Request.Header.Get(HTTPHeader_Fid)
		if fid == "" || len(fid) != len(pattern.FileHash{}) {
			n.Query("err", fmt.Sprintf("[%s] invalid fid: %s", clientIp, fid))
			c.JSON(http.StatusBadRequest, "invalid fid")
			return
		}
		path := utils.FindFile(n.GetDirs().FileDir, fid)
		if path == "" {
			n.Query("err", fmt.Sprintf("[%s] not found: %s", clientIp, fid))
			c.JSON(http.StatusNotFound, ERR_NotFound)
			return
		}
		c.JSON(http.StatusOK, nil)
		return
	}

	if len(queryName) != len(pattern.FileHash{}) {
		if account == "" {
			n.Query("err", fmt.Sprintf("[%s] %s", clientIp, ERR_MissAccount))
			c.JSON(http.StatusBadRequest, ERR_MissAccount)
			return
		}
		pkey, err := sutils.ParsingPublickey(account)
		if err != nil {
			n.Query("err", fmt.Sprintf("[%s] %s", clientIp, ERR_InvalidAccount))
			c.JSON(http.StatusBadRequest, ERR_InvalidAccount)
			return
		}
		// Query bucket
		if sutils.CheckBucketName(queryName) {
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
				owners[i], _ = sutils.EncodePublicKeyAsCessAccount(bucketInfo.Authority[i][:])
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
		var fileMetadata FileMetaData
		n.Query("info", fmt.Sprintf("[%s] Query file [%s] info", clientIp, queryName))
		fmeta, err := n.QueryFileMetadata(queryName)
		if err != nil {
			if err.Error() != pattern.ERR_Empty {
				n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, queryName, err))
				c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
				return
			}

			_, err = n.QueryStorageOrder(queryName)
			if err != nil {
				if err.Error() != pattern.ERR_Empty {
					n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, queryName, err))
					c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
					return
				}
				if !n.HasTrackFile(queryName) {
					n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: NotFount", clientIp, queryName))
					c.JSON(http.StatusNotFound, "NotFound")
					return
				}
			}
			n.Query("info", fmt.Sprintf("[%s] Query file [%s] info: storage order created", clientIp, queryName))
			c.JSON(http.StatusOK, "storage order created")
			return
		}

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
			fileMetadata.Owner[i].User, _ = sutils.EncodePublicKeyAsCessAccount(fmeta.Owner[i].User[:])
		}
		fileMetadata.SegmentList = make([]SegmentInfo, len(fmeta.SegmentList))
		for i := 0; i < len(fmeta.SegmentList); i++ {
			fileMetadata.SegmentList[i].FragmentList = make([]FragmentInfo, len(fmeta.SegmentList[i].FragmentList))
			fileMetadata.SegmentList[i].SegmentHash = string(fmeta.SegmentList[i].Hash[:])
			for j := 0; j < len(fmeta.SegmentList[i].FragmentList); j++ {
				fileMetadata.SegmentList[i].FragmentList[j].Avail = bool(fmeta.SegmentList[i].FragmentList[j].Avail)
				fileMetadata.SegmentList[i].FragmentList[j].FragmentHash = string(fmeta.SegmentList[i].FragmentList[j].Hash[:])
				fileMetadata.SegmentList[i].FragmentList[j].Miner, _ = sutils.EncodePublicKeyAsCessAccount(fmeta.SegmentList[i].FragmentList[j].Miner[:])
			}
		}
		n.Query("info", fmt.Sprintf("[%s] Query file [%s] info suc", clientIp, queryName))
		c.JSON(http.StatusOK, fileMetadata)
		return
	}

	// download file
	if operation == "download" {
		var err error
		var size uint64
		n.Query("info", fmt.Sprintf("[%s] Download file [%s]", clientIp, queryName))
		mycid, err := n.FidToCid(queryName)
		if err == nil {
			buf, err := n.GetLocalDataFromBlock(mycid)
			if err == nil {
				c.Data(200, "application/octet-stream", buf)
				return
			}
		}

		fpath := utils.FindFile(n.GetDirs().FileDir, queryName)
		fstat, err := os.Stat(fpath)
		if err == nil {
			if fstat.Size() > 0 {
				n.Query("info", fmt.Sprintf("[%s] Download file [%s] from cache", clientIp, queryName))
				c.File(fpath)
				return
			} else {
				os.Remove(fpath)
			}
		}

		var completion bool
		fmeta, err := n.QueryFileMetadata(queryName)
		if err != nil {
			if err.Error() != pattern.ERR_Empty {
				n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, queryName, err))
				c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
				return
			}
			order, err := n.QueryStorageOrder(queryName)
			if err != nil {
				if err.Error() != pattern.ERR_Empty {
					n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: %v", clientIp, queryName, err))
					c.JSON(http.StatusInternalServerError, ERR_RpcFailed)
					return
				}
				n.Query("err", fmt.Sprintf("[%s] Query file [%s] info: Not found", clientIp, queryName))
				c.JSON(http.StatusNotFound, ERR_NotFound)
				return
			} else {
				size = order.FileSize.Uint64()
				// segments, err := n.downloadFromBlock(order.NeededList)
				// if err != nil {
				// 	n.Query("err", fmt.Sprintf("[%s] downloadFromBlock [%s] info: Not found", clientIp, queryName))
				// 	c.JSON(404, "failed")
				// } else {
				// 	n.Query("info", fmt.Sprintf("[%s] Download file [%s] suc", clientIp, queryName))
				// 	c.JSON(200, "suc")
				// }
				// _ = segments
				// return
			}
		} else {
			completion = true
			size = fmeta.FileSize.Uint64()
		}

		fpath = filepath.Join(n.GetDirs().FileDir, queryName)
		peerList, _ := n.QueryDeossPeerIdList()
		if len(peerList) > 0 {
			for _, v := range peerList {
				addr, ok := n.GetPeer(v)
				if !ok {
					continue
				}
				if n.ID().Pretty() == v {
					continue
				}
				err = n.Connect(n.GetCtxQueryFromCtxCancel(), addr)
				if err != nil {
					continue
				}
				err = n.ReadDataAction(addr.ID, queryName, queryName, fpath, int64(size))
				if err != nil {
					continue
				}
				c.File(fpath)
				return
			}
		}

		if !completion {
			n.Query("err", fmt.Sprintf("[%s] Download file [%s] : %v", clientIp, queryName, "During the order transaction, please go to the original deoss to download the file."))
			c.JSON(http.StatusInternalServerError, "During the order transaction, please go to the original deoss to download the file.")
			return
		}

		// download from miner
		fpath, err = n.fetchFiles(queryName, n.GetDirs().FileDir, cipher)
		if err != nil {
			n.Query("err", fmt.Sprintf("[%s] Download file [%s] : %v", clientIp, queryName, err))
			c.JSON(http.StatusInternalServerError, "File download failed, please try again later.")
			return
		}
		n.Query("info", fmt.Sprintf("[%s] Download file [%s] suc", clientIp, queryName))
		c.File(fpath)
		return
	}
	n.Query("err", fmt.Sprintf("[%s] [%s] %s", clientIp, queryName, ERR_HeadOperation))
	c.JSON(http.StatusBadRequest, ERR_HeadOperation)
	return
}

func (n *Node) fetchFiles(roothash, dir, cipher string) (string, error) {
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
		acc, err = sutils.EncodePublicKeyAsCessAccount(v.User[:])
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
			err = n.Connect(n.GetCtxQueryFromCtxCancel(), addr)
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
				err = erasure.RSRestore(segmentpath, fragmentpaths)
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
				if cipher != "" {
					buf, err = crypte.AesCbcDecrypt(buf, []byte(cipher))
					if err != nil {
						return "", err
					}
				}
				if (writecount + 1) >= len(fmeta.SegmentList) {
					if cipher != "" {
						f.Write(buf[:(fmeta.FileSize.Uint64() - uint64(writecount*(pattern.SegmentSize-16)))])
					} else {
						f.Write(buf[:(fmeta.FileSize.Uint64() - uint64(writecount*pattern.SegmentSize))])
					}
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

// func (n *Node) downloadFromBlock(segmentList []pattern.SegmentList) ([]string, error) {
// 	var segmentPaths = make([]string, len(segmentList))
// 	var fragmentsData = make([][]byte, len(segmentList[0].FragmentHash))
// 	for sk, segment := range segmentList {
// 		for fk, fragment := range segment.FragmentHash {
// 			fragmentsData[fk] = nil
// 			n.Query("info", fmt.Sprintf("Will download fragment %s from block", string(fragment[:])))
// 			fragmentCid, err := n.FidToCid(string(fragment[:]))
// 			if err != nil {
// 				continue
// 			}
// 			n.Query("info", fmt.Sprintf("Will download fragment's cid is %s", fragmentCid))
// 			ctxTout, cancelFunc := context.WithTimeout(n.GetCtxQueryFromCtxCancel(), time.Second*5)
// 			defer cancelFunc()
// 			fragmentsData[fk], err = n.GetDataFromBlock(ctxTout, fragmentCid)
// 			if err != nil {
// 				continue
// 			}
// 			n.Query("info", fmt.Sprintf("Download fragment %s suc", string(fragment[:])))
// 		}
// 		var segmentPath = filepath.Join(n.Workspace(), "file", string(segment.SegmentHash[:]))
// 		err := erasure.RSRestoreData(segmentPath, fragmentsData)
// 		if err != nil {
// 			return segmentPaths, err
// 		}
// 		segmentPaths[sk] = segmentPath
// 	}
// 	return segmentPaths, nil
// }
