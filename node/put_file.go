/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
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
	defer c.Request.Body.Close()

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
	bucketName := c.Request.Header.Get(HTTPHeader_Bucket)
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

	pkey, code, err := verifySignature(n, account, ethAccount, message, signature)
	if err != nil {
		n.Logput("err", clientIp+" verifySignature: "+err.Error())
		c.JSON(code, err)
		return
	}

	if !sutils.CheckBucketName(bucketName) {
		n.Logput("err", clientIp+" CheckBucketName: "+bucketName)
		c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
		return
	}

	code, err = checkAuth(n, pkey)
	if err != nil {
		n.Logput("err", clientIp+" checkAuth: "+err.Error())
		c.JSON(code, err)
		return
	}

	code, err = checkSapce(n, pkey, territoryName, contentLength, 30)
	if err != nil {
		n.Logput("err", clientIp+" checkSapce: "+err.Error())
		c.JSON(code, err)
		return
	}

	cacheDir, fpath, code, err := createCacheDir(n, account)
	if err != nil {
		n.Logput("err", clientIp+" createCacheDir: "+err.Error())
		c.JSON(code, err)
		return
	}

	filename, length, code, err := saveFormFileToFile(c, fpath)
	if err != nil {
		n.Logput("err", clientIp+" saveFormFileToFile: "+err.Error())
		c.JSON(code, err)
		return
	}

	segment, fid, err := process.FullProcessing(fpath, cipher, cacheDir)
	if err != nil {
		n.Logput("err", clientIp+" FullProcessing: "+err.Error())
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	n.Logput("info", clientIp+" fid: "+fid)

	duplicate, code, err := checkDuplicates(n, fid, pkey)
	if err != nil {
		n.Logput("err", clientIp+" checkDuplicates: "+err.Error())
		c.JSON(code, err)
		return
	}

	newPath := filepath.Join(n.GetDirs().FileDir, fid)
	err = os.Rename(fpath, newPath)
	if err != nil {
		n.Logput("err", clientIp+" Rename: "+err.Error())
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	switch duplicate {
	case Duplicate1:
		blockhash, err := n.PlaceStorageOrder(fid, filename, bucketName, territoryName, segment, pkey, uint64(length))
		if err != nil {
			n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
			c.JSON(http.StatusInternalServerError, err)
			return
		}
		n.Logput("info", clientIp+" duplicate file: "+fid+" storage order hash: "+blockhash)
		c.JSON(http.StatusOK, map[string]string{"fid": fid})
		return
	case Duplicate2:
		n.Logput("info", clientIp+" duplicate file: "+fid)
		c.JSON(http.StatusOK, map[string]string{"fid": fid})
		return
	}

	code, err = saveToTrackFile(n, fid, filename, bucketName, territoryName, cacheDir, cipher, segment, pkey, uint64(length))
	if err != nil {
		n.Logput("err", clientIp+" saveToTrackFile: "+err.Error())
		c.JSON(code, err)
		return
	}

	err = n.MoveFileToCache(fid, newPath)
	if err != nil {
		n.Logput("err", clientIp+" MoveFileToCache: "+err.Error())
	}

	blockhash, err := n.PlaceStorageOrder(fid, filename, bucketName, territoryName, segment, pkey, uint64(length))
	if err != nil {
		n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	n.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	c.JSON(http.StatusOK, map[string]string{"fid": fid})
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

func saveFormFileToFile(c *gin.Context, file string) (string, int64, int, error) {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return "", 0, http.StatusInternalServerError, err
	}
	defer f.Close()
	formfile, fileHeder, err := c.Request.FormFile("file")
	if err != nil {
		return "", 0, http.StatusBadRequest, err
	}
	filename := fileHeder.Filename
	if strings.Contains(filename, "%") {
		filename, err = url.PathUnescape(filename)
		if err != nil {
			filename = fileHeder.Filename
		}
	}
	if len(filename) > sconfig.MaxBucketNameLength {
		return filename, 0, http.StatusBadRequest, errors.New(ERR_FileNameTooLang)
	}
	if len(filename) < sconfig.MinBucketNameLength {
		return filename, 0, http.StatusBadRequest, errors.New(ERR_FileNameTooShort)
	}
	length, err := io.Copy(f, formfile)
	if err != nil {
		return filename, 0, http.StatusBadRequest, err
	}
	return filename, length, http.StatusOK, nil
}

// func (n *Node) ProcessFile(file, file_name, bucket_name, account, cipher string, pkey []byte, c *gin.Context) (int, error) {
// 	fstat, err := os.Stat(file)
// 	if err != nil {
// 		return http.StatusInternalServerError, err
// 	}

// 	if fstat.Size() == 0 {
// 		return http.StatusBadRequest, errors.New(ERR_BodyEmptyFile)
// 	}

// 	segmentInfo, roothash, err := process.ShardedEncryptionProcessing(fpath, cipher)
// 	if err != nil {
// 		return http.StatusInternalServerError, err
// 	}

// 	ok, err := n.deduplication(pkey, segmentInfo, roothash, filename, bucketName, uint64(fstat.Size()))
// 	if err != nil {
// 		if strings.Contains(err.Error(), "[GenerateStorageOrder]") {
// 			n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
// 			c.JSON(http.StatusForbidden, ERR_RpcFailed)
// 			return
// 		}
// 		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
// 		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
// 		return
// 	}
// 	if ok {
// 		n.Upfile("info", fmt.Sprintf("[%v] [%s] uploaded successfully", clientIp, roothash))
// 		c.JSON(http.StatusOK, roothash)
// 		return
// 	}

// 	roothashDir := filepath.Join(n.GetDirs().FileDir, account, roothash)
// 	_, err = os.Stat(roothashDir)
// 	if err == nil {
// 		if ok := n.HasTrackFile(roothash); ok {
// 			err = n.MoveFileToCache(roothash, filepath.Join(roothashDir, roothash)) //move file to cache
// 			if err != nil {
// 				n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
// 			}
// 			c.JSON(http.StatusOK, roothash)
// 			n.Upfile("info", fmt.Sprintf("[%v] [%s] uploaded successfully", clientIp, roothash))
// 			return
// 		}
// 	}

// 	err = os.MkdirAll(roothashDir, 0755)
// 	if err != nil {
// 		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
// 		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
// 		return
// 	}

// 	err = utils.RenameDir(filepath.Dir(fpath), roothashDir)
// 	if err != nil {
// 		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
// 		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
// 		return
// 	}

// 	err = os.Rename(filepath.Join(roothashDir, filepath.Base(fpath)), filepath.Join(roothashDir, roothash))
// 	if err != nil {
// 		os.RemoveAll(roothashDir)
// 		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
// 		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
// 		return
// 	}

// 	err = n.MoveFileToCache(roothash, filepath.Join(roothashDir, roothash)) //move file to cache
// 	if err != nil {
// 		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
// 	}

// 	for i := 0; i < len(segmentInfo); i++ {
// 		segmentInfo[i].SegmentHash = filepath.Join(roothashDir, filepath.Base(segmentInfo[i].SegmentHash))
// 		for j := 0; j < len(segmentInfo[i].FragmentHash); j++ {
// 			segmentInfo[i].FragmentHash[j] = filepath.Join(roothashDir, filepath.Base(segmentInfo[i].FragmentHash[j]))
// 		}
// 	}

// 	var recordInfo = &RecordInfo{
// 		Segment:       segmentInfo,
// 		Owner:         pkey,
// 		Fid:           roothash,
// 		FileName:      filename,
// 		BucketName:    bucketName,
// 		TerritoryName: territoryName,
// 		FileSize:      uint64(fstat.Size()),
// 		PutFlag:       false,
// 		Duplicate:     false,
// 	}

// 	b, err := json.Marshal(recordInfo)
// 	if err != nil {
// 		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
// 		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
// 		return
// 	}

// 	err = n.WriteTrackFile(roothash, b)
// 	if err != nil {
// 		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
// 		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
// 		return
// 	}

// 	txhash, err := n.GenerateStorageOrder(
// 		roothash,
// 		recordInfo.SegmentInfo,
// 		recordInfo.Owner,
// 		recordInfo.Filename,
// 		recordInfo.Buckname,
// 		recordInfo.Filesize,
// 	)
// 	if err != nil {
// 		n.Upfile("err", fmt.Sprintf("[%s] GenerateStorageOrder failed, tx: %s err: %v", roothash, txhash, err))
// 	} else {
// 		n.Upfile("info", fmt.Sprintf("[%s] GenerateStorageOrder suc: %s", roothash, txhash))
// 	}

// 	n.Upfile("info", fmt.Sprintf("[%v] [%s] uploaded successfully", clientIp, roothash))
// 	c.JSON(http.StatusOK, roothash)
// }

// func (n *Node) deduplication(pkey []byte, segmentInfo []chain.SegmentDataInfo, roothash, filename, bucketname string, filesize uint64) (bool, error) {
// 	fmeta, err := n.QueryFile(roothash, -1)
// 	if err == nil {
// 		for _, v := range fmeta.Owner {
// 			if sutils.CompareSlice(v.User[:], pkey) {
// 				return true, nil
// 			}
// 		}
// 		_, err = n.GenerateStorageOrder(roothash, nil, pkey, filename, bucketname, filesize)
// 		if err != nil {
// 			return false, errors.Wrapf(err, "[GenerateStorageOrder]")
// 		}
// 		return true, nil
// 	}

// 	order, err := n.QueryDealMap(roothash, -1)
// 	if err == nil {
// 		if sutils.CompareSlice(order.User.User[:], pkey) {
// 			return true, nil
// 		}

// 		_, err = os.Stat(filepath.Join(n.trackDir, roothash))
// 		if err == nil {
// 			return false, errors.New(ERR_DuplicateOrder)
// 		}

// 		var record RecordInfo
// 		record.SegmentInfo = segmentInfo
// 		record.Owner = pkey
// 		record.Roothash = roothash
// 		record.Filename = filename
// 		record.Buckname = bucketname
// 		record.Putflag = false
// 		record.Count = 0
// 		record.Duplicate = true

// 		f, err := os.Create(filepath.Join(n.trackDir, roothash))
// 		if err != nil {
// 			return false, errors.Wrapf(err, "[create file]")
// 		}
// 		defer f.Close()

// 		b, err := json.Marshal(&record)
// 		if err != nil {
// 			return false, errors.Wrapf(err, "[marshal data]")
// 		}
// 		_, err = f.Write(b)
// 		if err != nil {
// 			return false, errors.Wrapf(err, "[write file]")
// 		}
// 		err = f.Sync()
// 		if err != nil {
// 			return false, errors.Wrapf(err, "[sync file]")
// 		}
// 		return true, nil
// 	}

// 	return false, nil
// }
