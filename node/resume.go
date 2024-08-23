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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/DeOSS/common/utils"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (n *Node) ResumeUpload(c *gin.Context) {
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
	filename := c.Param(HTTP_ParameterName)
	if filename == "" {
		n.Logput("err", clientIp+" empty file name")
		c.JSON(http.StatusBadRequest, "empty file name")
		return
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
	bucketName := c.Request.Header.Get(HTTPHeader_Bucket)
	territoryName := c.Request.Header.Get(HTTPHeader_Territory)
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

	pkey, code, err := verifySignature(n, account, ethAccount, message, signature)
	if err != nil {
		n.Logput("err", clientIp+" verifySignature: "+err.Error())
		c.JSON(code, err.Error())
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
		c.JSON(code, err.Error())
		return
	}

	code, err = checkSapce(n, pkey, territoryName, contentLength, 30)
	if err != nil {
		n.Logput("err", clientIp+" checkSapce: "+err.Error())
		c.JSON(code, err.Error())
		return
	}

	dir := filepath.Join(n.fileDir, account)
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		n.Logput("err", clientIp+" MkdirAll: "+err.Error())
		c.JSON(500, ERR_InternalServer)
		return
	}
	filePath := filepath.Join(dir, filename)
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		n.Logput("err", clientIp+" OpenFile: "+err.Error())
		c.JSON(500, ERR_InternalServer)
		return
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	fstat, err := f.Stat()
	if err != nil {
		n.Logput("err", clientIp+" Stat: "+err.Error())
		c.JSON(500, ERR_InternalServer)
		return
	}

	rangeHeader := c.GetHeader("Content-Range")
	if rangeHeader == "" {
		n.Logput("err", clientIp+" Missing Content-Range heade")
		c.String(http.StatusBadRequest, "Missing Content-Range header")
		return
	}

	rangeParts := strings.Split(rangeHeader, " ")
	if len(rangeParts) != 2 || !strings.HasPrefix(rangeParts[0], "bytes") {
		n.Logput("err", clientIp+" Invalid Content-Range format: "+rangeHeader)
		c.String(http.StatusBadRequest, "Invalid Content-Range format")
		return
	}

	rangeInfo := strings.Split(rangeParts[1], "/")
	if len(rangeInfo) != 2 {
		n.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		c.String(http.StatusBadRequest, "Invalid byte range")
		return
	}

	total, err := strconv.ParseInt(rangeInfo[1], 10, 64)
	if err != nil {
		n.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		c.String(http.StatusBadRequest, "Invalid byte range")
		return
	}

	byteRange := strings.Split(rangeInfo[0], "-")
	if len(byteRange) != 2 {
		n.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		c.String(http.StatusBadRequest, "Invalid byte range")
		return
	}

	start, err := strconv.ParseInt(byteRange[0], 10, 64)
	if err != nil || start < 0 {
		n.Logput("err", clientIp+" Invalid start range: "+rangeHeader)
		c.String(http.StatusBadRequest, "Invalid start byte")
		return
	}

	if start == 0 && fstat.Size() > 0 {
		n.Logput("err", clientIp+" Invalid start range: "+rangeHeader)
		c.Header("Content-Range", fmt.Sprintf("bytes 0-%d/%d", fstat.Size()-1, total))
		c.String(http.StatusBadRequest, "Invalid start byte")
		return
	}

	end, err := strconv.ParseInt(byteRange[1], 10, 64)
	if err != nil || end < start || end > total || end < fstat.Size() {
		fmt.Println("start: ", start, "end: ", end, "total: ", total, "file_size: ", fstat.Size())
		n.Logput("err", clientIp+" Invalid end range: "+rangeHeader)
		c.Header("Content-Range", fmt.Sprintf("bytes 0-%d/%d", fstat.Size()-1, total))
		c.String(http.StatusBadRequest, "Invalid end byte")
		return
	}

	_, err = f.Seek(start, io.SeekStart)
	if err != nil {
		n.Logput("err", clientIp+" f.Seek: "+err.Error())
		c.String(http.StatusBadRequest, "Failed to seek file to start")
		return
	}

	_, err = io.CopyN(f, c.Request.Body, end-start+1)
	if err != nil {
		n.Logput("err", clientIp+" CopyN: "+err.Error())
		c.String(http.StatusInternalServerError, "Failed to write to file")
		return
	}

	if end+1 < total {
		n.Logput("info", fmt.Sprintf("%s Received bytes: %d-%d", clientIp, start, end))
		c.Header("Content-Range", rangeHeader)
		c.String(http.StatusPermanentRedirect, fmt.Sprintf("Received bytes %d-%d", start, end))
		return
	}

	n.Logput("info", fmt.Sprintf("%s Received bytes: %d-%d\n", clientIp, start, end))

	cacherDir := filepath.Join(n.fileDir, account, uuid.NewString())

	segment, fid, err := process.FullProcessing(filePath, cipher, cacherDir)
	if err != nil {
		n.Logput("err", clientIp+" FullProcessing: "+err.Error())
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	n.Logput("info", clientIp+" fid: "+fid)

	duplicate, code, err := checkDuplicates(n, fid, pkey)
	if err != nil {
		n.Logput("err", clientIp+" checkDuplicates: "+err.Error())
		c.JSON(code, err.Error())
		return
	}

	newPath := filepath.Join(n.fileDir, fid)
	err = os.Rename(filePath, newPath)
	if err != nil {
		n.Logput("err", clientIp+" Rename: "+err.Error())
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	_, err = os.Stat(newPath)
	if err != nil {
		n.Logput("err", clientIp+" "+err.Error())
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	n.Logput("info", clientIp+" new file path: "+newPath)

	switch duplicate {
	case Duplicate1:
		blockhash, err := n.PlaceStorageOrder(fid, filename, bucketName, territoryName, segment, pkey, uint64(total))
		if err != nil {
			n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
			c.JSON(http.StatusInternalServerError, err.Error())
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

	code, err = saveToTrackFile(n, fid, filename, bucketName, territoryName, cacherDir, cipher, segment, pkey, uint64(total), shuntminer, points)
	if err != nil {
		n.Logput("err", clientIp+" saveToTrackFile: "+err.Error())
		c.JSON(code, err.Error())
		return
	}

	blockhash, err := n.PlaceStorageOrder(fid, filename, bucketName, territoryName, segment, pkey, uint64(total))
	if err != nil {
		n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}
	n.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	c.JSON(http.StatusOK, map[string]string{"fid": fid})
}
