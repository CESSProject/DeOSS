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
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
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

func (n *Node) Put_file(c *gin.Context) {
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

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}
	bucketName := c.Request.Header.Get(HTTPHeader_BucketName)
	territoryName := c.Request.Header.Get(HTTPHeader_Territory)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)
	contentLength := c.Request.ContentLength
	n.Logput("info", utils.StringBuilder(400, clientIp, account, ethAccount, bucketName, territoryName, cipher, message, signature))
	if contentLength <= 0 {
		n.Logput("err", clientIp+" "+ERR_EmptyFile)
		c.JSON(http.StatusBadRequest, ERR_EmptyFile)
		return
	}

	pkey, code, err := checkUserParamsAndGetPubkey(n, c, account, ethAccount, message, signature, bucketName, cipher)
	if err != nil {
		n.Logput("err", clientIp+" checkUserParamsAndGetPubkey: "+err.Error())
		c.JSON(code, err)
		return
	}

	// verify the space is authorized
	code, err = checkAuth(n, c, pkey)
	if err != nil {
		n.Logput("err", clientIp+" checkAuth: "+err.Error())
		c.JSON(code, err)
		return
	}

	if contentLength == 0 {
		blockHash, err := n.CreateBucket(pkey, bucketName)
		if err != nil {
			n.Logput("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		n.Logput("info", clientIp+" create bucket ["+bucketName+"] suc: "+blockHash)
		if len(blockHash) != (chain.FileHashLen + 2) {
			c.JSON(http.StatusOK, "bucket already exists")
		} else {
			c.JSON(http.StatusOK, map[string]string{"block hash:": blockHash})
		}
		return
	}

	code, err = checkSapce(n, c, pkey, territoryName, contentLength, 30)
	if err != nil {
		n.Logput("err", clientIp+" "+err.Error())
		c.JSON(code, err)
		return
	}

	savedir, fpath, code, err := createCacheDir(n, account)
	if err != nil {
		n.Logput("err", clientIp+" createCacheDir: "+err.Error())
		c.JSON(code, err)
		return
	}

	filename := ""
	formfile, fileHeder, err := c.Request.FormFile("file")
	if err != nil {
		n.Logput("err", clientIp+" FormFile: "+err.Error())
		if strings.Contains(err.Error(), "no space left on device") {
			c.JSON(http.StatusForbidden, ERR_DeviceSpaceNoLeft)
			return
		}
		if err.Error() != http.ErrNotMultipart.ErrorString {
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		buf, _ := io.ReadAll(c.Request.Body)
		if len(buf) == 0 {
			blockHash, err := n.CreateBucket(pkey, bucketName)
			if err != nil {
				n.Logput("err", clientIp+" CreateBucket: "+err.Error())
				c.JSON(http.StatusBadRequest, err.Error())
				return
			}
			n.Logput("info", clientIp+" create bucket ["+bucketName+"] suc: "+blockHash)
			c.JSON(http.StatusOK, map[string]string{"Block hash:": blockHash})
			return
		}
		// save body content
		err = sutils.WriteBufToFile(buf, fpath)
		if err != nil {
			n.Logput("err", clientIp+" WriteBufToFile: "+err.Error())
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		filename = "object"
	} else {
		filename = fileHeder.Filename
		if strings.Contains(filename, "%") {
			filename, err = url.PathUnescape(filename)
			if err != nil {
				n.Logput("err", clientIp+" PathUnescape: "+err.Error())
				c.JSON(http.StatusBadRequest, "unescape filename failed")
				return
			}
			n.Logput("info", clientIp+" file name: "+filename)
		}
		if len(filename) > sconfig.MaxBucketNameLength {
			n.Logput("err", clientIp+" "+ERR_FileNameTooLang)
			c.JSON(http.StatusBadRequest, ERR_FileNameTooLang)
			return
		}
		if len(filename) < sconfig.MinBucketNameLength {
			n.Logput("err", clientIp+" "+ERR_FileNameTooShort)
			c.JSON(http.StatusBadRequest, ERR_FileNameTooShort)
			return
		}

		f, err := os.Create(fpath)
		if err != nil {
			n.Logput("err", clientIp+" os.Create: "+err.Error())
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		_, err = io.Copy(f, formfile)
		if err != nil {
			f.Close()
			n.Logput("err", clientIp+" io.Copy: "+err.Error())
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		f.Close()
		f = nil
	}
	//n.fileProcess(filename, bucketName, fpath, account, cipher, pkey, c)
	segmentInfo, roothash, err := process.ShardedEncryptionProcessing(fpath, cipher)
	if err != nil {
		return http.StatusInternalServerError, err
	}
}

func createCacheDir(n *Node, account string) (string, string, int, error) {
	var (
		err      error
		cacheDir string
		fpath    string
	)
	for {
		cacheDir = filepath.Join(n.GetDirs().FileDir, account, time.Now().Format(time.TimeOnly))
		_, err = os.Stat(cacheDir)
		if err != nil {
			err = os.MkdirAll(cacheDir, 0755)
			if err != nil {
				return cacheDir, fpath, http.StatusInternalServerError, err
			}
		} else {
			time.Sleep(time.Second)
			continue
		}
		fpath = filepath.Join(cacheDir, fmt.Sprintf("%v", time.Now().Unix()))
		break
	}
	return cacheDir, fpath, http.StatusOK, nil
}

func saveToFile(c *gin.Context, n *Node, file string, bucket_name string, pkey []byte) (string, int, error) {
	filename := ""
	fileHeder, err := c.FormFile("file")
	if err != nil {
		if strings.Contains(err.Error(), "no space left on device") {
			return filename, http.StatusForbidden, err
		}
		if err.Error() != http.ErrNotMultipart.ErrorString {
			return filename, http.StatusBadRequest, err
		}
		buf, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return filename, http.StatusBadRequest, err
		}
		if len(buf) == 0 {
			blockHash, err := n.CreateBucket(pkey, bucket_name)
			if err != nil {
				return filename, http.StatusBadRequest, errors.Wrap(err, "CreateBucket")
			}
			n.Logput("info", clientIp+" create bucket ["+bucketName+"] suc: "+blockHash)
			c.JSON(http.StatusOK, map[string]string{"Block hash:": blockHash})
			return filename, http.StatusOK, nil
		}
		// save body content
		err = sutils.WriteBufToFile(buf, fpath)
		if err != nil {
			n.Logput("err", clientIp+" WriteBufToFile: "+err.Error())
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		filename = "object"
	}

	filename = fileHeder.Filename

	filename = fileHeder.Filename
	if strings.Contains(filename, "%") {
		filename, err = url.PathUnescape(filename)
		if err != nil {
			n.Logput("err", clientIp+" PathUnescape: "+err.Error())
			c.JSON(http.StatusBadRequest, "unescape filename failed")
			return
		}
		n.Logput("info", clientIp+" file name: "+filename)
	}
	if len(filename) > sconfig.MaxBucketNameLength {
		n.Logput("err", clientIp+" "+ERR_FileNameTooLang)
		c.JSON(http.StatusBadRequest, ERR_FileNameTooLang)
		return
	}
	if len(filename) < sconfig.MinBucketNameLength {
		n.Logput("err", clientIp+" "+ERR_FileNameTooShort)
		c.JSON(http.StatusBadRequest, ERR_FileNameTooShort)
		return
	}

	err = c.SaveUploadedFile(fileHeder, file)
	if err != nil {
		c.JSON(http.StatusB, ERR_InternalServer)
	}
}

func (n *Node) ProcessFile(file, file_name, bucket_name, account, cipher string, pkey []byte, c *gin.Context) (int, error) {
	fstat, err := os.Stat(file)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if fstat.Size() == 0 {
		return http.StatusBadRequest, errors.New(ERR_BodyEmptyFile)
	}

	segmentInfo, roothash, err := process.ShardedEncryptionProcessing(fpath, cipher)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	ok, err := n.deduplication(pkey, segmentInfo, roothash, filename, bucketName, uint64(fstat.Size()))
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
		if ok := n.HasTrackFile(roothash); ok {
			err = n.MoveFileToCache(roothash, filepath.Join(roothashDir, roothash)) //move file to cache
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			}
			c.JSON(http.StatusOK, roothash)
			n.Upfile("info", fmt.Sprintf("[%v] [%s] uploaded successfully", clientIp, roothash))
			return
		}
	}

	err = os.MkdirAll(roothashDir, 0755)
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

	err = n.MoveFileToCache(roothash, filepath.Join(roothashDir, roothash)) //move file to cache
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
	}

	for i := 0; i < len(segmentInfo); i++ {
		segmentInfo[i].SegmentHash = filepath.Join(roothashDir, filepath.Base(segmentInfo[i].SegmentHash))
		for j := 0; j < len(segmentInfo[i].FragmentHash); j++ {
			segmentInfo[i].FragmentHash[j] = filepath.Join(roothashDir, filepath.Base(segmentInfo[i].FragmentHash[j]))
		}
	}

	var recordInfo = &RecordInfo{
		Segment:       segmentInfo,
		Owner:         pkey,
		Fid:           roothash,
		FileName:      filename,
		BucketName:    bucketName,
		TerritoryName: territoryName,
		FileSize:      uint64(fstat.Size()),
		PutFlag:       false,
		Duplicate:     false,
	}

	b, err := json.Marshal(recordInfo)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	err = n.WriteTrackFile(roothash, b)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	txhash, err := n.GenerateStorageOrder(
		roothash,
		recordInfo.SegmentInfo,
		recordInfo.Owner,
		recordInfo.Filename,
		recordInfo.Buckname,
		recordInfo.Filesize,
	)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%s] GenerateStorageOrder failed, tx: %s err: %v", roothash, txhash, err))
	} else {
		n.Upfile("info", fmt.Sprintf("[%s] GenerateStorageOrder suc: %s", roothash, txhash))
	}

	n.Upfile("info", fmt.Sprintf("[%v] [%s] uploaded successfully", clientIp, roothash))
	c.JSON(http.StatusOK, roothash)
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
