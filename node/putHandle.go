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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const max_concurrent_req = 10

var max_concurrent_req_ch chan bool

func init() {
	max_concurrent_req_ch = make(chan bool, 10)
	for i := 0; i < max_concurrent_req; i++ {
		max_concurrent_req_ch <- true
	}
}

// putHandle
func (n *Node) putHandle(c *gin.Context) {
	account := c.Request.Header.Get(HTTPHeader_Account)
	if account != "cXkdXokcMa32BAYkmsGjhRGA2CYmLUN2pq69U8k9taXsQPHGp" &&
		account != "cXic3WhctsJ9cExmjE9vog49xaLuVbDLcFi2odeEnvV5Sbq4f" {
		if _, ok := <-max_concurrent_req_ch; !ok {
			c.JSON(http.StatusTooManyRequests, "service is busy, please try again later.")
			return
		}
		defer func() { max_concurrent_req_ch <- true }()
	}

	if !checkDeOSSStatus(n, c) {
		return
	}

	var (
		err      error
		fpath    string
		savedir  string
		filename string
		pkey     []byte
	)

	// record client ip
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" || clientIp == " " {
		clientIp = c.ClientIP()
	}
	n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, INFO_PutRequest))

	// verify the authorization
	bucketName := c.Request.Header.Get(HTTPHeader_BucketName)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	contentLength := c.Request.ContentLength
	n.Upfile("info", fmt.Sprintf("[%v] Acc: %s", clientIp, account))
	n.Upfile("info", fmt.Sprintf("[%v] BucketName: %s", clientIp, bucketName))
	n.Upfile("info", fmt.Sprintf("[%v] ContentLength: %d", clientIp, contentLength))

	pkey = checkUserParamsAndGetPubkey(n, c, account, bucketName, cipher, clientIp)
	if len(pkey) == 0 {
		return
	}

	// verify the space is authorized
	if !checkAuth(n, c, pkey, clientIp) {
		return
	}

	if contentLength == 0 {
		txHash, err := n.CreateBucket(pkey, bucketName)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		n.Upfile("info", fmt.Sprintf("[%v] create bucket [%v] successfully: %v", clientIp, bucketName, txHash))
		if len(txHash) != (chain.FileHashLen + 2) {
			c.JSON(http.StatusOK, "bucket already exists")
		} else {
			c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
		}
		return
	}

	if !checkSapce(n, c, pkey, clientIp, contentLength*15/10, 30) {
		return
	}

	mem, err := utils.GetSysMemAvailable()
	if err == nil {
		if uint64(contentLength) > uint64(mem*90/100) {
			if uint64(contentLength) < MaxMemUsed {
				n.Upfile("err", fmt.Sprintf("[%v] %v, size: [%d] mem: [%d]", clientIp, ERR_SysMemNoLeft, contentLength, mem))
				c.JSON(http.StatusForbidden, ERR_SysMemNoLeft)
				return
			}
		}
	}

	// verify disk space availability
	if contentLength > MaxMemUsed {
		freeSpace, err := utils.GetDirFreeSpace("/tmp")
		if err == nil {
			if uint64(contentLength+sconfig.SIZE_1MiB*16) > freeSpace {
				n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_DeviceSpaceNoLeft))
				c.JSON(http.StatusForbidden, ERR_DeviceSpaceNoLeft)
				return
			}
		}
	}

	for {
		savedir = filepath.Join(n.GetDirs().FileDir, account, fmt.Sprintf("%s-%s", uuid.New().String(), uuid.New().String()))
		_, err = os.Stat(savedir)
		if err != nil {
			err = os.MkdirAll(savedir, 0755)
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
		if strings.Contains(err.Error(), "no space left on device") {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err.Error()))
			c.JSON(http.StatusForbidden, ERR_DeviceSpaceNoLeft)
			return
		}
		if err.Error() != http.ErrNotMultipart.ErrorString {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		buf, _ := io.ReadAll(c.Request.Body)
		if len(buf) == 0 {
			txHash, err := n.CreateBucket(pkey, bucketName)
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
				c.JSON(http.StatusBadRequest, err.Error())
				return
			}
			n.Upfile("info", fmt.Sprintf("[%v] create bucket [%v] successfully: %v", clientIp, bucketName, txHash))
			c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
			return
		}
		// save body content
		err = sutils.WriteBufToFile(buf, fpath)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
	} else {
		filename = fileHeder.Filename
		if strings.Contains(filename, "%") {
			filename, err = url.PathUnescape(filename)
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, "unescape filename failed"))
				c.JSON(http.StatusBadRequest, "unescape filename failed")
				return
			}
			n.Upfile("info", fmt.Sprintf("[%v] file name: %s", clientIp, filename))
		}
		if len(filename) > sconfig.MaxBucketNameLength {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_FileNameTooLang))
			c.JSON(http.StatusBadRequest, ERR_FileNameTooLang)
			return
		}

		f, err := os.Create(fpath)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		_, err = io.Copy(f, formfile)
		if err != nil {
			f.Close()
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		f.Close()
	}
	n.fileProcess(filename, bucketName, fpath, account, cipher, pkey, c)
}

func (n *Node) deduplication(pkey []byte, segmentInfo []chain.SegmentDataInfo, roothash, filename, bucketname string, filesize uint64) (bool, error) {
	fmeta, err := n.QueryFile(roothash, -1)
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

	order, err := n.QueryDealMap(roothash, -1)
	if err == nil {
		if sutils.CompareSlice(order.User.User[:], pkey) {
			return true, nil
		}

		_, err = os.Stat(filepath.Join(n.trackDir, roothash))
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

		f, err := os.Create(filepath.Join(n.trackDir, roothash))
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
