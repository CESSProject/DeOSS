/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/CESSProject/DeOSS/common/utils"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
)

func (n *Node) Put_shunt(c *gin.Context) {
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
	filename := c.Request.Header.Get(HTTPHeader_Fname)
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

	n.Logput("info", clientIp+" cache file path: "+fpath)

	fname, length, code, err := saveFormFileToFile(c, fpath)
	if err != nil {
		n.Logput("err", clientIp+" saveFormFileToFile: "+err.Error())
		c.JSON(code, err)
		return
	}

	if filename == "" {
		filename = fname
	}

	if len(filename) > sconfig.MaxBucketNameLength {
		n.Logput("err", clientIp+" "+ERR_FileNameTooLang+": "+filename)
		c.JSON(http.StatusBadRequest, ERR_FileNameTooLang)
		return
	}
	if len(filename) < sconfig.MinBucketNameLength {
		n.Logput("err", clientIp+" "+ERR_FileNameTooShort+": "+filename)
		c.JSON(http.StatusBadRequest, ERR_FileNameTooShort)
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

	_, err = os.Stat(newPath)
	if err != nil {
		n.Logput("err", clientIp+" "+err.Error())
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	n.Logput("info", clientIp+" new file path: "+newPath)

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
