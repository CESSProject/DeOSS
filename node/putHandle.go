/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"io/fs"
	"log"

	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type ChunksInfo struct {
	BlockNum      int       `json:"block_num"`
	SavedBlocks   []bool    `json:"saved_blocks"`
	Finished      int       `json:"finished"`
	SavedFileSize int64     `json:"saved_file_size"`
	FileName      string    `json:"file_name"`
	TotalSize     int64     `json:"total_size"`
	FlushTime     time.Time `json:"flush_time"`
}

const max_concurrent_req = 10

var max_concurrent_req_ch chan bool

func init() {
	max_concurrent_req_ch = make(chan bool, 10)
	for i := 0; i < max_concurrent_req; i++ {
		max_concurrent_req_ch <- true
	}
}

func checkUserParamsAndGetPubkey(n *Node, c *gin.Context, account, bucketName, cipher, clientIp string) []byte {
	var (
		pkey []byte
		err  error
	)

	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)

	if err = n.AccessControl(account); err != nil {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusForbidden, err.Error())
		return nil
	}

	if ethAccount != "" {
		ethAccInSian, err := VerifyEthSign(message, signature)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, err.Error())
			return nil
		}
		if ethAccInSian != ethAccount {
			n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, "ETH signature verification failed"))
			c.JSON(http.StatusBadRequest, "ETH signature verification failed")
			return nil
		}
		pkey, err = sutils.ParsingPublickey(account)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, fmt.Sprintf("invalid cess account: %s", account))
			return nil
		}
	} else {
		pkey, err = n.VerifyAccountSignature(account, message, signature)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, err.Error())
			return nil
		}
	}

	if !sutils.CheckBucketName(bucketName) {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_HeaderFieldBucketName))
		c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
		return nil
	}

	// verify mem availability
	if len(cipher) > 32 {
		n.Upfile("err", fmt.Sprintf("[%v] The length of cipher cannot exceed 32", clientIp))
		c.JSON(http.StatusBadRequest, "The length of cipher cannot exceed 32")
		return nil
	}

	// verify the bucket name

	if strings.Contains(bucketName, " ") {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_HeaderFieldBucketName))
		c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
		return nil
	}
	return pkey
}

func checkSapce(n *Node, c *gin.Context, pkey []byte, clientIp string, usedSpace int64, deadLine uint32) bool {
	userInfo, err := n.QueryUserOwnedSpace(pkey, -1)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_NoSpace))
			c.JSON(http.StatusForbidden, ERR_NoSpace)
			return false
		}
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusForbidden, ERR_RpcFailed)
		return false
	}

	blockheight, err := n.QueryBlockNumber("")
	if err != nil {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusForbidden, ERR_RpcFailed)
		return false
	}

	if uint32(userInfo.Deadline) < (blockheight + deadLine) {
		n.Upfile("info", fmt.Sprintf("[%v] %v [%d] [%d]", clientIp, ERR_SpaceExpiresSoon, userInfo.Deadline, blockheight))
		c.JSON(http.StatusForbidden, ERR_SpaceExpiresSoon)
		return false
	}

	remainingSpace, err := strconv.ParseUint(userInfo.RemainingSpace.String(), 10, 64)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return false
	}

	if usedSpace > int64(remainingSpace) {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_NotEnoughSpace))
		c.JSON(http.StatusForbidden, ERR_NotEnoughSpace)
		return false
	}
	return true
}

func checkAuth(n *Node, c *gin.Context, pkey []byte, clientIp string) bool {
	authAccs, err := n.QueryAuthorityList(pkey, -1)
	var flag bool
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_SpaceNotAuth))
			c.JSON(http.StatusForbidden, ERR_SpaceNotAuth)
			return false
		}
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return false
	}

	for _, v := range authAccs {
		if sutils.CompareSlice(n.GetSignatureAccPulickey(), v[:]) {
			flag = true
			break
		}
	}
	if !flag {
		n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, ERR_SpaceNotAuth))
		c.JSON(http.StatusForbidden, fmt.Sprintf("please authorize your space usage to %s", n.GetSignatureAcc()))
		return false
	}
	return true
}

func checkExpiredFiles(rootDir string) bool {
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return true
	}
	count := 0
	var chunkInfo ChunksInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(rootDir, entry.Name(), "chunk-info")
		if _, err := os.Stat(metaPath); err != nil {
			continue
		}
		count++
		if count >= 10 {
			log.Print("user uploading files ", count)
			return false
		}
		buf, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		err = json.Unmarshal(buf, &chunkInfo)
		if err != nil {
			continue
		}
		if time.Since(chunkInfo.FlushTime) >= time.Hour*24 {
			os.RemoveAll(filepath.Join(rootDir, entry.Name()))
		}
	}
	return true
}

func checkDeOSSStatus(n *Node, c *gin.Context) bool {
	if _, ok := <-max_concurrent_req_ch; !ok {
		c.JSON(http.StatusTooManyRequests, "service is busy, please try again later.")
		return false
	}
	defer func() { max_concurrent_req_ch <- true }()

	if n.GetBalances() <= 1 {
		c.JSON(http.StatusInternalServerError, "service balance is insufficient, please try again later.")
		return false
	}

	if !n.GetRpcState() {
		c.JSON(http.StatusInternalServerError, "service rpc connection failed, please try again later.")
		return false
	}
	return true
}

// putHandle
func (n *Node) putHandle(c *gin.Context) {

	if !checkDeOSSStatus(n, c) {
		return
	}
	var (
		err      error
		clientIp string
		fpath    string
		savedir  string
		filename string
		pkey     []byte
	)

	// record client ip
	clientIp = c.Request.Header.Get("X-Forwarded-For")
	n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, INFO_PutRequest))

	// verify the authorization
	account := c.Request.Header.Get(HTTPHeader_Account)
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

func (n *Node) putChunksHandle(c *gin.Context) {
	var (
		err        error
		pkey       []byte
		chunksInfo ChunksInfo
	)

	if !checkDeOSSStatus(n, c) {
		return
	}

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	account := c.Request.Header.Get(HTTPHeader_Account)
	bucketName := c.Request.Header.Get(HTTPHeader_BucketName)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	blockIdx, _ := strconv.Atoi(c.Request.Header.Get(HTTPHeader_BIdx))
	blockNum, _ := strconv.Atoi(c.Request.Header.Get(HTTPHeader_BNum))
	totalSize, _ := strconv.ParseInt(c.Request.Header.Get(HTTPHeader_TSize), 10, 64)
	filename := c.Request.Header.Get(HTTPHeader_Fname)
	contentLength := c.Request.ContentLength

	pkey = checkUserParamsAndGetPubkey(n, c, account, bucketName, cipher, clientIp)
	if len(pkey) == 0 {
		return
	}

	mem, err := utils.GetSysMemAvailable()
	if err == nil {
		if uint64(contentLength) > uint64(mem*90/100) {
			if uint64(contentLength) < MaxMemUsed {
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
				c.JSON(http.StatusForbidden, ERR_DeviceSpaceNoLeft)
				return
			}
		}
	}

	if blockIdx%7 == 0 && !checkExpiredFiles(filepath.Join(n.GetDirs().FileDir, account)) {
		c.JSON(http.StatusForbidden, "the number of files being uploaded exceeds the limit")
		return
	}

	//get chunks info record
	fdir, err := sutils.CalcSHA256(append([]byte(bucketName+filename), []byte(account)...))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}
	savedir := filepath.Join(n.GetDirs().FileDir, account, fdir)
	_, err = os.Stat(savedir)
	if err != nil {
		err = os.MkdirAll(savedir, 0755)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
	}

	fpath := filepath.Join(savedir, filename)
	_, err = os.Stat(filepath.Join(savedir, "chunk-info"))
	if err != nil {
		if blockNum <= 0 {
			c.JSON(http.StatusForbidden, "bad block number")
			return
		}
		if totalSize <= 0 {
			c.JSON(http.StatusForbidden, "bad file total size")
			return
		}
		if !checkSapce(n, c, pkey, clientIp, int64(totalSize), 14400) {
			return
		}
		if !checkAuth(n, c, pkey, clientIp) {
			return
		}
		chunksInfo = ChunksInfo{
			BlockNum:    blockNum,
			FileName:    filename,
			SavedBlocks: make([]bool, blockNum),
			TotalSize:   int64(totalSize),
			FlushTime:   time.Now(),
		}
	} else {
		jbytes, err := os.ReadFile(filepath.Join(savedir, "chunk-info"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		err = json.Unmarshal(jbytes, &chunksInfo)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
	}

	if blockIdx < 0 || blockIdx >= chunksInfo.BlockNum {
		c.JSON(http.StatusBadRequest, fmt.Sprint("bad chunk index", blockIdx))
		return
	}

	if chunksInfo.SavedBlocks[blockIdx] {
		c.JSON(http.StatusOK, fmt.Sprint("chunk ", blockIdx, " already exists"))
		return
	}

	formfile, fileHeder, err := c.Request.FormFile("file")
	if err != nil {
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
			txHash, err := n.CreateBucket(pkey, bucketName)
			if err != nil {
				c.JSON(http.StatusBadRequest, err.Error())
				return
			}
			c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
			return
		}
		// save body content
		err = sutils.WriteBufToFile(buf, fmt.Sprintf("%s-CESS-chunk-file-%d", fileHeder.Filename, blockIdx))
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
	} else {

		if fileHeder.Size+chunksInfo.SavedFileSize > chunksInfo.TotalSize {
			c.JSON(http.StatusBadRequest, "bad chunk size")
			return

		}
		if len(chunksInfo.FileName) > sconfig.MaxBucketNameLength {
			c.JSON(http.StatusBadRequest, ERR_FileNameTooLang)
			return
		}
		f, err := os.Create(filepath.Join(savedir, fmt.Sprintf("chunk-file-%d", blockIdx)))
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		_, err = io.Copy(f, formfile)
		if err != nil {
			f.Close()
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		f.Close()
	}

	if chunksInfo.BlockNum == chunksInfo.Finished+1 {
		defer os.RemoveAll(savedir)
		// combine chunks
		var size int64
		f, err := os.Create(fpath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		entries, err := os.ReadDir(savedir)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		entryMap := make(map[int]fs.DirEntry)
		for _, e := range entries {
			if e.IsDir() || !strings.Contains(e.Name(), "chunk-file-") {
				continue
			}
			s := strings.Split(e.Name(), "-")
			idx, err := strconv.Atoi(s[len(s)-1])
			if err != nil {
				continue
			}
			entryMap[idx] = e
		}
		for i := 0; i < chunksInfo.BlockNum; i++ {
			e, ok := entryMap[i]
			if !ok {
				f.Close()
				os.Remove(fpath)
				c.JSON(http.StatusBadRequest, fmt.Sprintf("file chunk %d does not exist", i))
				return
			}
			chunk, err := os.Open(filepath.Join(savedir, e.Name()))
			if err != nil {
				f.Close()
				os.Remove(fpath)
				c.JSON(http.StatusInternalServerError, ERR_InternalServer)
				return
			}
			n, err := io.Copy(f, chunk)
			chunk.Close()
			if err != nil {
				f.Close()
				os.Remove(fpath)
				c.JSON(http.StatusInternalServerError, ERR_InternalServer)
				return
			}
			size += int64(n)
		}
		f.Close()
		if size != chunksInfo.TotalSize {
			os.Remove(fpath)
			c.JSON(http.StatusBadRequest, fmt.Sprintf("file size mismatch,expected %d, actual %d", totalSize, size))
			return
		}
	} else {
		chunksInfo.SavedFileSize += fileHeder.Size
		chunksInfo.SavedBlocks[blockIdx] = true
		chunksInfo.Finished++
		chunksInfo.FlushTime = time.Now()
		jbytes, err := json.Marshal(chunksInfo)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		err = sutils.WriteBufToFile(jbytes, filepath.Join(savedir, "chunk-info"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
		c.JSON(http.StatusOK, blockIdx)
		return
	}

	n.fileProcess(filename, bucketName, fpath, account, cipher, pkey, c)
}

func (n *Node) fileProcess(filename, bucketName, fpath, account, cipher string, pkey []byte, c *gin.Context) {

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if filename == "" {
		filename = "null"
	}

	if len(filename) < 3 {
		filename += ".ces"
	}

	fstat, err := os.Stat(fpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	if fstat.Size() == 0 {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_BodyEmptyFile))
		c.JSON(http.StatusBadRequest, ERR_BodyEmptyFile)
		return
	}

	segmentInfo, roothash, err := process.ShardedEncryptionProcessing(fpath, cipher)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	n.Upfile("info", fmt.Sprintf("[%v] segmentInfo: %v", clientIp, segmentInfo))

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
