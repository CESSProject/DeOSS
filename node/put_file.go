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

	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/DeOSS/common/utils"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
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
	if !n.IsHighPriorityAccount(account) {
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
	shuntminers := c.Request.Header.Values(HTTPHeader_Miner)
	longitudes := c.Request.Header.Values(HTTPHeader_Longitude)
	latitudes := c.Request.Header.Values(HTTPHeader_Latitude)
	contentLength := c.Request.ContentLength
	n.Logput("info", utils.StringBuilder(400, clientIp, account, ethAccount, bucketName, territoryName, cipher, message, signature))
	shuntminerslength := len(shuntminers)
	if shuntminerslength > 0 {
		n.Logput("info", fmt.Sprintf("shuntminers: %d, %v", shuntminerslength, shuntminers))
	}
	points, err := coordinate.ConvertToRange(longitudes, latitudes)
	if err != nil {
		n.Logput("err", clientIp+" "+err.Error())
	}
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

	newPath := filepath.Join(n.fileDir, fid)
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

	var shuntminer = ShuntMiner{
		Miners:   shuntminers,
		Complete: make([]bool, len(shuntminers)),
	}

	code, err = saveToTrackFile(n, fid, filename, bucketName, territoryName, cacheDir, cipher, segment, pkey, uint64(length), shuntminer, points)
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
		cacheDir = filepath.Join(n.fileDir, account, time.Now().Format(time.DateTime))
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
	length, err := io.Copy(f, formfile)
	if err != nil {
		return filename, 0, http.StatusBadRequest, err
	}
	return filename, length, http.StatusOK, nil
}
