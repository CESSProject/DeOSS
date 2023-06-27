/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type RecordInfo struct {
	SegmentInfo []pattern.SegmentDataInfo `json:"segmentInfo"`
	Owner       []byte                    `json:"owner"`
	Roothash    string                    `json:"roothash"`
	Filename    string                    `json:"filename"`
	Buckname    string                    `json:"buckname"`
	Filesize    uint64                    `json:"filesize"`
	Putflag     bool                      `json:"putflag"`
	Count       uint8                     `json:"count"`
	Duplicate   bool                      `json:"duplicate"`
}

// It is used to authorize users
func (n *Node) putHandle(c *gin.Context) {
	var (
		ok       bool
		err      error
		clientIp string
		account  string
		fpath    string
		roothash string
		savedir  string
		filename string
		pkey     []byte
		respMsg  = &RespMsg{}
	)

	clientIp = c.ClientIP()
	n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, INFO_PutRequest))

	// verify token
	token := c.Request.Header.Get(HTTPHeader_Authorization)
	account, pkey, err = n.verifyToken(token, respMsg)
	if err != nil {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(respMsg.Code, err.Error())
		return
	}

	// verify bucket name
	bucketName := c.Request.Header.Get(HTTPHeader_BucketName)
	if !sutils.CheckBucketName(bucketName) {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_HeaderFieldBucketName))
		c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
		return
	}

	contentLength := c.Request.ContentLength

	userInfo, err := n.QueryUserSpaceSt(pkey)
	if err != nil {
		if err.Error() == pattern.ERR_Empty {
			n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_AccountNotExist))
			c.JSON(http.StatusForbidden, ERR_AccountNotExist)
			return
		}
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusForbidden, ERR_RpcFailed)
		return
	}

	blockheight, err := n.QueryBlockHeight("")
	if err != nil {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusForbidden, ERR_RpcFailed)
		return
	}

	if userInfo.Deadline < (blockheight + 30) {
		n.Upfile("info", fmt.Sprintf("[%v] %v [%d] [%d]", clientIp, ERR_SpaceExpiresSoon, userInfo.Deadline, blockheight))
		c.JSON(http.StatusForbidden, ERR_SpaceExpiresSoon)
		return
	}

	usedSpace := contentLength * 15 / 10
	remainingSpace, err := strconv.ParseUint(userInfo.RemainingSpace, 10, 64)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	if usedSpace > int64(remainingSpace) {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_NotEnoughSpace))
		c.JSON(http.StatusForbidden, ERR_NotEnoughSpace)
		return
	}

	for {
		savedir = filepath.Join(n.GetDirs().FileDir, account, fmt.Sprintf("%s-%s", uuid.New().String(), uuid.New().String()))
		_, err = os.Stat(savedir)
		if err != nil {
			err = os.MkdirAll(savedir, pattern.DirMode)
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err.Error()))
				c.JSON(http.StatusInternalServerError, ERR_InternalServer)
				return
			}
		} else {
			continue
		}
		fpath = filepath.Join(savedir, fmt.Sprintf("%v", time.Now().Unix()))
		defer os.Remove(savedir)
		break
	}

	formfile, fileHeder, err := c.Request.FormFile("file")
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err.Error()))
		if err.Error() != http.ErrNotMultipart.ErrorString {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		buf, _ := ioutil.ReadAll(c.Request.Body)
		if len(buf) == 0 {
			txHash, err := n.CreateBucket(pkey, bucketName)
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", c.ClientIP(), err))
				c.JSON(http.StatusBadRequest, err.Error())
				return
			}
			n.Upfile("info", fmt.Sprintf("[%v] create bucket [%v] successfully: %v", clientIp, bucketName, txHash))
			c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
			return
		}
		// save body content
		f, err := os.Create(fpath)
		if err != nil {
			fmt.Println(err)
			c.JSON(500, err.Error())
			return
		}
		defer func() {
			if f != nil {
				f.Close()
			}
		}()
		f.Write(buf)
		f.Sync()
		f.Close()
		f = nil
	} else {
		filename = fileHeder.Filename
		// Create file
		f, err := os.Create(fpath)
		if err != nil {
			fmt.Println(err)
			c.JSON(500, err.Error())
			return
		}

		defer func() {
			if f != nil {
				f.Close()
			}
		}()

		// save form file
		var num int
		var buf = make([]byte, 4*1024*1024)
		for {
			num, err = formfile.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				c.JSON(400, "InvalidParameter.File")
				return
			}
			if num == 0 {
				continue
			}
			f.Write(buf[:num])
		}
		f.Sync()
		f.Close()
		f = nil
	}

	fstat, err := os.Stat(fpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	segmentInfo, roothash, err := n.ProcessingData(fpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	if filename == "" {
		filename = roothash
	}

	ok, err = n.deduplication(pkey, segmentInfo, roothash, filename, bucketName, uint64(fstat.Size()))
	if err != nil {
		if strings.Contains(err.Error(), "[GenerateStorageOrder]") {
			n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(http.StatusForbidden, ERR_RpcFailed)
			return
		}
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}
	if ok {
		n.Upfile("info", fmt.Sprintf("[%v] [%s] uploaded successfully", clientIp, roothash))
		c.JSON(http.StatusOK, roothash)
		return
	}

	roothashDir := filepath.Join(n.GetDirs().FileDir, account, roothash)
	_, err = os.Stat(roothashDir)
	if err == nil {
		_, err = os.Stat(filepath.Join(n.TrackDir, roothash))
		if err == nil {
			c.JSON(http.StatusOK, roothash)
			n.Upfile("info", fmt.Sprintf("[%v] [%s] uploaded successfully", clientIp, roothash))
			return
		}
	}

	err = os.MkdirAll(roothashDir, pattern.DirMode)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	err = utils.RenameDir(filepath.Dir(fpath), roothashDir)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	err = os.Rename(filepath.Join(roothashDir, filepath.Base(fpath)), filepath.Join(roothashDir, roothash))
	if err != nil {
		os.RemoveAll(roothashDir)
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	for i := 0; i < len(segmentInfo); i++ {
		segmentInfo[i].SegmentHash = filepath.Join(roothashDir, filepath.Base(segmentInfo[i].SegmentHash))
		for j := 0; j < len(segmentInfo[i].FragmentHash); j++ {
			segmentInfo[i].FragmentHash[j] = filepath.Join(roothashDir, filepath.Base(segmentInfo[i].FragmentHash[j]))
		}
	}

	var recordInfo = &RecordInfo{
		SegmentInfo: segmentInfo,
		Owner:       pkey,
		Roothash:    roothash,
		Filename:    filename,
		Buckname:    bucketName,
		Filesize:    uint64(fstat.Size()),
		Putflag:     false,
		Count:       0,
		Duplicate:   false,
	}

	f, err := os.Create(filepath.Join(n.TrackDir, roothash))
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}
	defer f.Close()

	b, err := json.Marshal(recordInfo)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}
	_, err = f.Write(b)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}
	err = f.Sync()
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	n.Upfile("info", fmt.Sprintf("[%v] [%s] uploaded successfully", clientIp, roothash))
	c.JSON(http.StatusOK, roothash)
	return
}

func (n *Node) deduplication(pkey []byte, segmentInfo []pattern.SegmentDataInfo, roothash, filename, bucketname string, filesize uint64) (bool, error) {
	fmeta, err := n.QueryFileMetadata(roothash)
	if err == nil {
		for _, v := range fmeta.Owner {
			if sutils.CompareSlice(v.User[:], pkey) {
				return true, nil
			}
		}
		_, err = n.GenerateStorageOrder(roothash, nil, pkey, filename, bucketname, filesize)
		if err != nil {
			return false, errors.Wrapf(err, "[GenerateStorageOrder]")
		}

		return true, nil
	}

	order, err := n.QueryStorageOrder(roothash)
	if err == nil {
		if sutils.CompareSlice(order.User.User[:], pkey) {
			return true, nil
		}

		_, err = os.Stat(filepath.Join(n.TrackDir, roothash))
		if err == nil {
			return false, errors.New(ERR_DuplicateOrder)
		}

		var record RecordInfo
		record.SegmentInfo = segmentInfo
		record.Owner = pkey
		record.Roothash = roothash
		record.Filename = filename
		record.Buckname = bucketname
		record.Putflag = false
		record.Count = 0
		record.Duplicate = true

		f, err := os.Create(filepath.Join(n.TrackDir, roothash))
		if err != nil {
			return false, errors.Wrapf(err, "[create file]")
		}
		defer f.Close()

		b, err := json.Marshal(&record)
		if err != nil {
			return false, errors.Wrapf(err, "[marshal data]")
		}
		_, err = f.Write(b)
		if err != nil {
			return false, errors.Wrapf(err, "[write file]")
		}
		err = f.Sync()
		if err != nil {
			return false, errors.Wrapf(err, "[sync file]")
		}
		return true, nil
	}

	return false, nil
}
