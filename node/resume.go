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
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (n *Node) ResumeUpload(c *gin.Context) {
	defer c.Request.Body.Close()
	respData := RespType{
		Code: http.StatusOK,
		Msg:  "ok",
	}

	account := c.Request.Header.Get(HTTPHeader_Account)
	if !n.IsHighPriorityAccount(account) {
		if _, ok := <-max_concurrent_req_ch; !ok {
			respData.Code = http.StatusTooManyRequests
			respData.Msg = ERR_ServerBusy
			c.JSON(http.StatusTooManyRequests, respData)
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
		n.Logput("err", clientIp+" "+ERR_EmptyFileName)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_EmptyFileName
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	if strings.Contains(filename, "%") {
		name, err := url.PathUnescape(filename)
		if err == nil {
			filename = name
		}
	}

	if len(filename) > sconfig.MaxBucketNameLength {
		n.Logput("err", clientIp+" "+ERR_FileNameTooLang+": "+filename)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_FileNameTooLang
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	if len(filename) < sconfig.MinBucketNameLength {
		n.Logput("err", clientIp+" "+ERR_FileNameTooShort+": "+filename)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_FileNameTooShort
		c.JSON(http.StatusBadRequest, respData)
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
		respData.Code = code
		respData.Msg = err.Error()
		c.JSON(code, err.Error())
		return
	}

	if !sutils.CheckBucketName(bucketName) {
		n.Logput("err", clientIp+" CheckBucketName: "+bucketName)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_HeaderFieldBucketName
		c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
		return
	}

	code, err = checkAuth(n, pkey)
	if err != nil {
		n.Logput("err", clientIp+" checkAuth: "+err.Error())
		respData.Code = code
		respData.Msg = err.Error()
		c.JSON(code, err.Error())
		return
	}

	code, err = checkSapce(n, pkey, territoryName, contentLength, 30)
	if err != nil {
		n.Logput("err", clientIp+" checkSapce: "+err.Error())
		respData.Code = code
		respData.Msg = err.Error()
		c.JSON(code, respData)
		return
	}

	dir := filepath.Join(n.fileDir, account)
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		n.Logput("err", clientIp+" MkdirAll: "+err.Error())
		respData.Code = http.StatusInternalServerError
		respData.Msg = ERR_InternalServer
		c.JSON(http.StatusInternalServerError, respData)
		return
	}

	rangeHeader := c.GetHeader("Content-Range")
	if rangeHeader == "" {
		n.Logput("err", clientIp+" "+ERR_MissingContentRange)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_MissingContentRange
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	rangeParts := strings.Split(rangeHeader, " ")
	if len(rangeParts) != 2 || !strings.HasPrefix(rangeParts[0], "bytes") {
		n.Logput("err", clientIp+" Invalid Content-Range format: "+rangeHeader)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_IllegalContentRange
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	rangeInfo := strings.Split(rangeParts[1], "/")
	if len(rangeInfo) != 2 {
		n.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_IllegalContentRange
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	total, err := strconv.ParseInt(rangeInfo[1], 10, 64)
	if err != nil {
		n.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_IllegalContentRange
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	byteRange := strings.Split(rangeInfo[0], "-")
	if len(byteRange) != 2 {
		n.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_IllegalContentRange
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	start, err := strconv.ParseInt(byteRange[0], 10, 64)
	if err != nil || start < 0 {
		n.Logput("err", clientIp+" Invalid start range: "+rangeHeader)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_IllegalContentRange
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	filePath := filepath.Join(dir, fmt.Sprintf("%s-%s", filename, rangeInfo[1]))
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		n.Logput("err", clientIp+" OpenFile: "+err.Error())
		respData.Code = http.StatusInternalServerError
		respData.Msg = ERR_InternalServer
		c.JSON(http.StatusInternalServerError, respData)
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
		respData.Code = http.StatusInternalServerError
		respData.Msg = ERR_InternalServer
		c.JSON(http.StatusInternalServerError, respData)
		return
	}

	// if fstat.Size() == total {
	// 	n.Logput("info", clientIp+" upload suc")
	// 	respData.Code = http.StatusOK
	// 	respData.Msg = "ok"
	// 	c.String(http.StatusOK, "Invalid start byte")
	// 	return
	// }

	end, err := strconv.ParseInt(byteRange[1], 10, 64)
	if err != nil || end < start || end > total {
		// fmt.Println("start: ", start, "end: ", end, "total: ", total, "file_size: ", fstat.Size())
		n.Logput("err", clientIp+" Invalid end range: "+rangeHeader)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_IllegalContentRange
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	if start > fstat.Size() {
		n.Logput("err", clientIp+" Invalid start range: "+rangeHeader)
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_IllegalContentRange
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	_, err = f.Seek(start, io.SeekStart)
	if err != nil {
		n.Logput("err", clientIp+" f.Seek: "+err.Error())
		respData.Code = http.StatusInternalServerError
		respData.Msg = ERR_InternalServer
		c.JSON(http.StatusInternalServerError, respData)
		return
	}

	_, err = io.CopyN(f, c.Request.Body, end-start+1)
	if err != nil && err != io.EOF {
		n.Logput("err", clientIp+" CopyN: "+err.Error())
		respData.Code = http.StatusBadRequest
		respData.Msg = ERR_FailedToRecvData
		c.JSON(http.StatusBadRequest, respData)
		return
	}

	if end+1 < total {
		n.Logput("info", fmt.Sprintf("%s Received bytes: %s", clientIp, rangeHeader))
		c.Header("Content-Range", rangeHeader)
		respData.Code = http.StatusPermanentRedirect
		respData.Msg = "ok"
		c.JSON(http.StatusPermanentRedirect, respData)
		return
	}

	n.Logput("info", fmt.Sprintf("%s Received bytes: %s\n", clientIp, rangeHeader))

	uid := ""
	for {
		u, err := uuid.NewUUID()
		if err != nil {
			time.Sleep(time.Millisecond * 10)
			continue
		}
		uid = u.String()
		if uid != "" {
			break
		}
		time.Sleep(time.Millisecond * 10)
		continue
	}

	cacherDir := filepath.Join(n.fileDir, account, uid)

	segment, fid, err := process.FullProcessing(filePath, cipher, cacherDir)
	if err != nil {
		n.Logput("err", clientIp+" FullProcessing: "+err.Error())
		respData.Code = http.StatusInternalServerError
		respData.Msg = ERR_InternalServer
		c.JSON(http.StatusInternalServerError, respData)
		return
	}

	n.Logput("info", clientIp+" fid: "+fid)

	duplicate, code, err := checkDuplicates(n, fid, pkey)
	if err != nil {
		n.Logput("err", clientIp+" checkDuplicates: "+err.Error())
		respData.Code = code
		respData.Msg = ERR_RPCConnection
		c.JSON(code, respData)
		return
	}

	newPath := filepath.Join(n.fileDir, fid)
	err = os.Rename(filePath, newPath)
	if err != nil {
		n.Logput("err", clientIp+" Rename: "+err.Error())
		respData.Code = http.StatusInternalServerError
		respData.Msg = ERR_InternalServer
		c.JSON(http.StatusInternalServerError, respData)
		return
	}

	_, err = os.Stat(newPath)
	if err != nil {
		n.Logput("err", clientIp+" "+err.Error())
		respData.Code = http.StatusInternalServerError
		respData.Msg = ERR_InternalServer
		c.JSON(http.StatusInternalServerError, respData)
		return
	}

	n.Logput("info", clientIp+" new file path: "+newPath)
	respData.Code = http.StatusOK
	respData.Msg = "ok"
	respData.Data = map[string]string{"fid": fid}
	c.JSON(http.StatusOK, respData)
	return

	switch duplicate {
	case Duplicate1:
		blockhash := ""
		for i := 0; i < 3; i++ {
			blockhash, err = n.PlaceStorageOrder(fid, filename, bucketName, territoryName, segment, pkey, uint64(total))
			if err != nil {
				if strings.Contains(err.Error(), chain.ERR_RPC_CONNECTION.Error()) {
					err = n.ReconnectRpc()
					if err != nil {
						n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
						respData.Code = http.StatusInternalServerError
						respData.Msg = ERR_RPCConnection
						c.JSON(http.StatusInternalServerError, respData)
						return
					}
					continue
				}
				n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
				respData.Code = http.StatusInternalServerError
				respData.Msg = ERR_RPCConnection
				c.JSON(http.StatusInternalServerError, respData)
				return
			}
			n.Logput("info", clientIp+" duplicate file: "+fid+" storage order hash: "+blockhash)
			respData.Code = http.StatusOK
			respData.Msg = "ok"
			respData.Data = map[string]string{"fid": fid}
			c.JSON(http.StatusOK, respData)
			return
		}
		n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		respData.Code = http.StatusInternalServerError
		respData.Msg = ERR_RPCConnection
		c.JSON(http.StatusInternalServerError, respData)
		return
	case Duplicate2:
		n.Logput("info", clientIp+" duplicate file: "+fid)
		respData.Code = http.StatusOK
		respData.Msg = "ok"
		respData.Data = map[string]string{"fid": fid}
		c.JSON(http.StatusOK, respData)
		return
	}

	var shuntminer = ShuntMiner{
		Miners:   shuntminers,
		Complete: make([]bool, len(shuntminers)),
	}

	code, err = saveToTrackFile(n, fid, filename, bucketName, territoryName, cacherDir, cipher, segment, pkey, uint64(total), shuntminer, points)
	if err != nil {
		n.Logput("err", clientIp+" saveToTrackFile: "+err.Error())
		respData.Code = code
		respData.Msg = ERR_InternalServer
		c.JSON(code, respData)
		return
	}
	blockhash := ""
	for i := 0; i < 3; i++ {
		blockhash, err = n.PlaceStorageOrder(fid, filename, bucketName, territoryName, segment, pkey, uint64(total))
		if err != nil {
			if strings.Contains(err.Error(), chain.ERR_RPC_CONNECTION.Error()) {
				err = n.ReconnectRpc()
				if err != nil {
					n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
					respData.Code = http.StatusInternalServerError
					respData.Msg = ERR_RPCConnection
					c.JSON(http.StatusInternalServerError, respData)
					return
				}
				continue
			}
			n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
			respData.Code = http.StatusInternalServerError
			respData.Msg = ERR_RPCConnection
			c.JSON(http.StatusInternalServerError, respData)
			return
		}
		n.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
		respData.Code = http.StatusOK
		respData.Msg = "ok"
		respData.Data = map[string]string{"fid": fid}
		c.JSON(http.StatusOK, respData)
		return
	}
	n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
	respData.Code = http.StatusInternalServerError
	respData.Msg = ERR_RPCConnection
	c.JSON(http.StatusInternalServerError, respData)
	return
}
