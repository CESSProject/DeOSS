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
	"os"
	"path/filepath"

	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func (n *Node) Put_object(c *gin.Context) {
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
	filename := c.Request.Header.Get(HTTPHeader_Fname)
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
	if contentLength <= 0 {
		n.Logput("err", clientIp+" "+ERR_EmptyBody)
		c.JSON(http.StatusBadRequest, ERR_EmptyBody)
		return
	}
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
		c.JSON(code, err)
		return
	}

	if !sutils.CheckBucketName(bucketName) {
		n.Logput("err", clientIp+" CheckBucketName: "+bucketName)
		c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
		return
	}

	// verify the space is authorized
	code, err = checkAuth(n, pkey)
	if err != nil {
		n.Logput("err", clientIp+" checkAuth: "+err.Error())
		c.JSON(code, err)
		return
	}

	code, err = checkSapce(n, pkey, territoryName, contentLength, 30)
	if err != nil {
		n.Logput("err", clientIp+" "+err.Error())
		c.JSON(code, err)
		return
	}

	if filename == "" {
		filename = "object"
	}

	cacheDir, fpath, code, err := createCacheDir(n, account)
	if err != nil {
		n.Logput("err", clientIp+" createCacheDir: "+err.Error())
		c.JSON(code, err)
		return
	}

	length, code, err := saveObjectToFile(c, fpath)
	if err != nil {
		n.Logput("err", clientIp+" saveObjectToFile: "+err.Error())
		c.JSON(code, err)
		return
	}

	segmentInfo, fid, err := process.FullProcessing(fpath, cipher, cacheDir)
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

	switch duplicate {
	case Duplicate1:
		blockhash, err := n.PlaceStorageOrder(fid, filename, bucketName, territoryName, segmentInfo, pkey, uint64(length))
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
	code, err = saveToTrackFile(n, fid, filename, bucketName, territoryName, cacheDir, cipher, segmentInfo, pkey, uint64(length), shuntminer, points)
	if err != nil {
		n.Logput("err", clientIp+" saveToTrackFile: "+err.Error())
		c.JSON(code, err)
		return
	}

	err = n.MoveFileToCache(fid, newPath)
	if err != nil {
		n.Logput("err", clientIp+" MoveFileToCache: "+err.Error())
	}

	blockhash, err := n.PlaceStorageOrder(fid, filename, bucketName, territoryName, segmentInfo, pkey, uint64(length))
	if err != nil {
		n.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	n.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	c.JSON(http.StatusOK, map[string]string{"fid": fid})
}

func saveObjectToFile(c *gin.Context, file string) (int64, int, error) {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return 0, http.StatusInternalServerError, err
	}
	defer f.Close()
	length, err := io.Copy(f, c.Request.Body)
	if err != nil {
		return 0, http.StatusBadRequest, err
	}
	return length, http.StatusOK, nil
}

func checkDuplicates(n *Node, fid string, pkey []byte) (DuplicateType, int, error) {
	fmeta, err := n.QueryFile(fid, -1)
	if err != nil {
		if !errors.Is(err, chain.ERR_RPC_EMPTY_VALUE) {
			return Duplicate0, http.StatusInternalServerError, err
		}
		return Duplicate0, http.StatusOK, nil
	}
	for _, v := range fmeta.Owner {
		if sutils.CompareSlice(v.User[:], pkey) {
			return Duplicate2, http.StatusOK, nil
		}
	}
	return Duplicate1, http.StatusOK, nil
}

func saveToTrackFile(n *Node, fid, file_name, bucket_name, territory_name, cacheDir, cipher string, segment []chain.SegmentDataInfo, pkey []byte, size uint64, shuntminer ShuntMiner, points coordinate.Range) (int, error) {
	var recordInfo = &TrackerInfo{
		Segment:       segment,
		Owner:         pkey,
		ShuntMiner:    shuntminer,
		Points:        points,
		Fid:           fid,
		FileName:      file_name,
		BucketName:    bucket_name,
		TerritoryName: territory_name,
		CacheDir:      cacheDir,
		Cipher:        cipher,
		FileSize:      size,
		PutFlag:       false,
	}

	b, err := json.Marshal(recordInfo)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	err = n.WriteTrackFile(fid, b)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}
