/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"sync"

	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/crypte"
	"github.com/CESSProject/cess-go-sdk/core/erasure"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	cansproto "github.com/CESSProject/cess-go-tools/cans-proto"
	"github.com/gin-gonic/gin"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
)

const (
	CANS_PROTO_FLAG            = "CANS_PROTO_"
	CHUNK_FILE_FLAG            = "--CESS-chunk-file--"
	CANS_PROTO_HEADER          = "CanProtocol"
	CANS_SPLIT_FILE_HEADER     = "FileSplit"
	CANS_ARCHIVE_FORMAT_HEADER = "ArchiveFormat"
	FILE_METADATA_KEY          = "_file_metadata_"
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

type CansRequestParams struct {
	SegmentIndex int    `json:"segment_index"`
	SubFile      string `json:"sub_file"`
	Cipher       string `json:"cipher"`
}

var chunkReqLock *sync.Mutex
var chunkReq map[string]int64

func init() {
	chunkReqLock = new(sync.Mutex)
	chunkReq = make(map[string]int64, 10)
}

func (n *Node) PutChunksHandle(c *gin.Context) {
	account := c.Request.Header.Get(HTTPHeader_Account)
	chunkReqLock.Lock()
	_, ok := chunkReq[account]
	chunkReqLock.Unlock()
	if !ok {
		if _, has := <-max_concurrent_req_ch; !has {
			c.JSON(http.StatusTooManyRequests, "service is busy, please try again later.")
			return
		}
		defer func() { max_concurrent_req_ch <- true }()
		if !checkDeOSSStatus(n, c) {
			return
		}
	} else {
		chunkReqLock.Lock()
		chunkReq[account] = time.Now().Unix()
		chunkReqLock.Unlock()
	}

	var (
		err        error
		pkey       []byte
		chunksInfo ChunksInfo
	)

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	bucketName := c.Request.Header.Get(HTTPHeader_BucketName)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	blockIdx, _ := strconv.Atoi(c.Request.Header.Get(HTTPHeader_BIdx))
	blockNum, _ := strconv.Atoi(c.Request.Header.Get(HTTPHeader_BNum))
	totalSize, _ := strconv.ParseInt(c.Request.Header.Get(HTTPHeader_TSize), 10, 64)
	filename := c.Request.Header.Get(HTTPHeader_Fname)
	cansProto := c.Request.Header.Get(CANS_PROTO_HEADER)
	isSplit := c.Request.Header.Get(CANS_SPLIT_FILE_HEADER)
	archiveFormat := c.Request.Header.Get(CANS_ARCHIVE_FORMAT_HEADER)
	filename, err = url.QueryUnescape(filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	contentLength := c.Request.ContentLength

	if clientIp == "" || clientIp == " " {
		clientIp = c.ClientIP()
	}
	if cansProto == "true" && !strings.Contains(filename, CANS_PROTO_FLAG) {
		filename = fmt.Sprintf("%s%s", CANS_PROTO_FLAG, filename)
	}

	n.Upfile("info", fmt.Sprintf("[%v] file name: %s", clientIp, filename))
	if strings.Contains(filename, "%") {
		filename, err = url.PathUnescape(filename)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, "unescape filename failed"))
			c.JSON(http.StatusBadRequest, "unescape filename failed")
			return
		}
		n.Upfile("info", fmt.Sprintf("[%v] file name: %s", clientIp, filename))
	}

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
		if len(filename) > sconfig.MaxBucketNameLength {
			c.JSON(http.StatusBadRequest, ERR_FileNameTooLang)
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
		err = sutils.WriteBufToFile(buf, fmt.Sprintf("%s%s%d", fileHeder.Filename, CHUNK_FILE_FLAG, blockIdx))
		if err != nil {
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			return
		}
	} else {

		if fileHeder.Size+chunksInfo.SavedFileSize > chunksInfo.TotalSize {
			c.JSON(http.StatusBadRequest, "bad chunk size")
			return
		}
		f, err := os.Create(filepath.Join(savedir, fmt.Sprintf("%s%s%d", fileHeder.Filename, CHUNK_FILE_FLAG, blockIdx)))
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
		if cansProto == "true" {
			if err := os.Remove(filepath.Join(savedir, "chunk-info")); err != nil {
				c.JSON(http.StatusInternalServerError, err.Error())
			}
			beSplit := false
			if isSplit == "true" {
				beSplit = true
			}
			log.Println("savedir", savedir, "cipher", cipher)
			log.Println("filename", filename, "archiveFormat", archiveFormat, "issplit", beSplit)
			if err = cansproto.ArchiveCanFile(savedir, filename, archiveFormat, cipher != "", beSplit,
				func(s string) string {
					ss := strings.Split(s, CHUNK_FILE_FLAG)
					log.Println("entry path:", s)
					return ss[0]
				}, nil); err != nil {
				c.JSON(http.StatusInternalServerError, err.Error())
			}
		} else {
			func() {
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
					if e.IsDir() || !strings.Contains(e.Name(), CHUNK_FILE_FLAG) {
						continue
					}
					s := strings.Split(e.Name(), CHUNK_FILE_FLAG)
					idx, err := strconv.Atoi(s[len(s)-1])
					if err != nil {
						continue
					}
					entryMap[idx] = e
				}
				for i := 0; i < chunksInfo.BlockNum; i++ {
					if code, err := func() (int, error) {
						e, ok := entryMap[i]
						if !ok {
							return http.StatusBadRequest, fmt.Errorf("file chunk %d does not exist", i)
						}
						chunk, err := os.Open(filepath.Join(savedir, e.Name()))
						if err != nil {
							return http.StatusInternalServerError, fmt.Errorf(ERR_InternalServer)
						}
						defer chunk.Close()
						n, err := io.Copy(f, chunk)
						if err != nil {
							return http.StatusInternalServerError, fmt.Errorf(ERR_InternalServer)
						}
						size += int64(n)
						return 0, nil
					}(); err != nil {
						f.Close()
						os.Remove(fpath)
						c.JSON(code, err.Error())
						return
					}
				}
				f.Close()
				if size != chunksInfo.TotalSize {
					os.Remove(fpath)
					c.JSON(http.StatusBadRequest, fmt.Sprintf("file size mismatch,expected %d, actual %d", totalSize, size))
					return
				}
			}()
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

	chunkReqLock.Lock()
	delete(chunkReq, account)
	chunkReqLock.Unlock()
	n.fileProcess(filename, bucketName, fpath, account, cipher, pkey, c)
}

func (n *Node) GetCanFileHandle(c *gin.Context) {
	if _, ok := <-max_concurrent_get_ch; !ok {
		c.JSON(http.StatusTooManyRequests, "server is busy, please try again later.")
		return
	}
	defer func() { max_concurrent_get_ch <- true }()
	fid := c.Param(HTTP_ParameterName_Fid)
	var reqParams CansRequestParams
	if err := c.BindJSON(&reqParams); err != nil {
		c.JSON(http.StatusNotFound, fmt.Sprintf("bad json request params,%v", err))
		return
	}
	fdir := filepath.Join(n.GetDirs().FileDir, fid)
	if _, err := os.Stat(fdir); err != nil {
		if err = os.MkdirAll(fdir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
	}

	var boxMeta cansproto.BoxMetadata
	if mpath, err := n.GetCacheRecord(fmt.Sprintf("%s%s", fid, FILE_METADATA_KEY)); err == nil && mpath != "" {
		data, err := os.ReadFile(mpath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		err = json.Unmarshal(data, &boxMeta)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
	}

	if boxMeta.FileName == "" {
		segment0, err := n.GetSegment(fdir, fid, 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		if segment0 == "" {
			c.JSON(http.StatusInternalServerError, "can not found the first segment of file")
			return
		}
		bytes, err := os.ReadFile(segment0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		boxMeta, err = cansproto.ParseCanBoxMetadata(bytes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		jbytes, err := json.Marshal(boxMeta)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		if err = n.SaveDataToCache(fmt.Sprintf("%s%s", fid, FILE_METADATA_KEY), jbytes); err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
	}

	if reqParams.SubFile == "" {
		segmenti, err := n.GetSegment(fdir, fid, reqParams.SegmentIndex)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		if segmenti == "" {
			c.JSON(http.StatusInternalServerError, "can not found the first segment of file")
			return
		}
		//decrypto segment
		if reqParams.Cipher != "" {
			err = DecryptSegment(segmenti, reqParams.Cipher)
			if err != nil {
				c.JSON(http.StatusInternalServerError, err.Error())
				return
			}
		}
		c.File(filepath.Join(fdir, segmenti))
		return
	}

	record := -1
cans:
	for i, can := range boxMeta.Cans {
		for _, f := range can.Files {
			if strings.Contains(f.FileName, reqParams.SubFile) {
				record = i
				break cans
			}
		}
	}
	if record >= 0 {
		segmenti, err := n.GetSegment(fdir, fid, record)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		if segmenti == "" {
			c.JSON(http.StatusInternalServerError, "can not found the first segment of file")
			return
		}
		if reqParams.Cipher != "" {
			err = DecryptSegment(segmenti, reqParams.Cipher)
			if err != nil {
				c.JSON(http.StatusInternalServerError, err.Error())
				return
			}
		}
		fpath, err := cansproto.ExtractFileFromCan(segmenti, fdir, reqParams.SubFile, record, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, "can not found the first segment of file")
			return
		}
		c.File(fpath)
		os.Remove(fpath)
	}
}

func (n *Node) fileProcess(filename, bucketName, fpath, account, cipher string, pkey []byte, c *gin.Context) (int, error) {
	fstat, err := os.Stat(fpath)
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

func checkUserParamsAndGetPubkey(n *Node, c *gin.Context, account, ethAccount, message, signature, bucketName, cipher string) ([]byte, int, error) {
	var (
		pkey []byte
		err  error
	)

	if err = n.AccessControl(account); err != nil {
		return nil, http.StatusBadRequest, err
	}

	if ethAccount != "" {
		ethAccInSian, err := VerifyEthSign(message, signature)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		if ethAccInSian != ethAccount {
			return nil, http.StatusBadRequest, errors.New("ETH signature verification failed")
		}
		pkey, err = sutils.ParsingPublickey(account)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		if len(pkey) == 0 {
			return nil, http.StatusBadRequest, errors.New("invalid account")
		}
	} else {
		pkey, err = n.VerifyAccountSignature(account, message, signature)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		if len(pkey) == 0 {
			return nil, http.StatusBadRequest, errors.New("invalid signature")
		}
	}

	if !sutils.CheckBucketName(bucketName) {
		return pkey, http.StatusBadRequest, errors.New(ERR_HeaderFieldBucketName)
	}

	if len(cipher) > 32 {
		return pkey, http.StatusBadRequest, errors.New("the length of cipher cannot exceed 32")
	}

	return pkey, http.StatusOK, nil
}

func checkSapce(n *Node, c *gin.Context, pkey []byte, territoryName string, contentLength int64, deadLine uint32) (int, error) {
	territoryInfo, err := n.QueryTerritory(pkey, territoryName, -1)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			return http.StatusForbidden, errors.New(ERR_NoTerritory)
		}
		return http.StatusInternalServerError, errors.New(ERR_RpcFailed)
	}

	blockheight, err := n.QueryBlockNumber("")
	if err != nil {
		return http.StatusInternalServerError, errors.New(ERR_RpcFailed)
	}

	if uint32(territoryInfo.Deadline) < (blockheight + deadLine) {
		return http.StatusForbidden, errors.New(ERR_TerritoryExpiresSoon)
	}

	remainingSpace, err := strconv.ParseUint(territoryInfo.RemainingSpace.String(), 10, 64)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	countSegment := contentLength / sconfig.SegmentSize
	if contentLength%sconfig.SegmentSize != 0 {
		countSegment += 1
	}

	totalOccupiedSpace := uint64(countSegment) * sconfig.SegmentSize * 3

	if totalOccupiedSpace > remainingSpace {
		return http.StatusForbidden, errors.New(ERR_InsufficientTerritorySpace)
	}

	freeSpace, err := utils.GetDirFreeSpace("/tmp")
	if err == nil {
		if totalOccupiedSpace > freeSpace {
			return http.StatusForbidden, errors.New(ERR_DeviceSpaceNoLeft)
		}
	}

	return http.StatusOK, nil
}

func checkAuth(n *Node, c *gin.Context, pkey []byte) (int, error) {
	authAccs, err := n.QueryAuthorityList(pkey, -1)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			return http.StatusForbidden, errors.New(ERR_SpaceNotAuth)
		}
		return http.StatusInternalServerError, err
	}
	flag := false
	for _, v := range authAccs {
		if sutils.CompareSlice(n.GetSignatureAccPulickey(), v[:]) {
			flag = true
			break
		}
	}
	if !flag {
		return http.StatusForbidden, errors.Errorf("please authorize the gateway account: %s", n.GetSignatureAcc())
	}
	return http.StatusOK, nil
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
	if n.GetBalances() <= 1 {
		msg := `The gateway account balance is insufficient, please feedback to us:
		https://twitter.com/CESS_Storage
		https://t.me/CESS_Storage_official
		https://discord.gg/tkZ4gfrK`
		c.JSON(http.StatusInternalServerError, msg)
		return false
	}

	if !n.GetRpcState() {
		c.JSON(http.StatusInternalServerError, "RPC connection failed, please try again later.")
		return false
	}
	return true
}

func (n *Node) GetSegment(fdir, fhash string, sid int) (string, error) {
	var (
		fpath string
		err   error
	)
	if sid < 0 {
		return fpath, errors.Wrap(errors.New("bad segment index"), "get segment error")
	}

	if record, err := n.ParseTrackFile(fhash); err == nil {
		if sid < len(record.SegmentInfo) && record.SegmentInfo[sid].SegmentHash != "" {
			fpath = record.SegmentInfo[sid].SegmentHash
			if _, err = os.Stat(fpath); err == nil {
				return fpath, nil
			}
		}
	}

	fmeta, err := n.QueryFile(fhash, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			return fpath, errors.Wrap(errors.New(ERR_RpcFailed), "get segment error")
		}
		return fpath, errors.Wrap(err, "get segment error")
	}
	if sid > len(fmeta.SegmentList) {
		return "", errors.Wrap(errors.New("bad segment index"), "get segment error")
	}
	segment := fmeta.SegmentList[sid]

	fpath, err = n.GetCacheRecord(string(segment.Hash[:]))
	if err == nil && fpath != "" {
		if _, err = os.Stat(fpath); err == nil {
			return fpath, nil
		}
	}

	count := 0
	fgPaths := make([]string, 0)
	for _, fragment := range segment.FragmentList {
		if count >= sconfig.DataShards {
			break
		}
		miner, err := n.QueryMinerItems(fragment.Miner[:], -1)
		if err != nil {
			continue
		}
		fragmentPath := filepath.Join(fdir, string(fragment.Hash[:]))
		if err = n.ReadFileAction(
			peer.ID(miner.PeerId[:]), fhash, string(segment.Hash[:]),
			fragmentPath, sconfig.FragmentSize,
		); err != nil {
			continue
		}
		count++
		fgPaths = append(fgPaths, fragmentPath)
		defer os.Remove(fragmentPath)
	}
	if count < sconfig.DataShards {
		err := errors.New("not enough fragments were downloaded")
		return fpath, errors.Wrap(err, "get segment error")
	}
	fpath = filepath.Join(fdir, string(segment.Hash[:]))
	err = erasure.RSRestore(fpath, fgPaths)
	if err != nil {
		return fpath, errors.Wrap(err, "get segment error")
	}
	n.AddCacheRecord(string(segment.Hash[:]), fpath)
	return fpath, nil
}

func DecryptSegment(fpath, cipher string) error {
	bytes, err := os.ReadFile(fpath)
	if err != nil {
		return errors.Wrap(err, "decrypto segment error")
	}
	res, err := crypte.AesCbcDecrypt(bytes, []byte(cipher))
	if err != nil {
		return errors.Wrap(err, "decrypto segment error")
	}
	err = os.WriteFile(fpath, res, 0755)
	return errors.Wrap(err, "decrypto segment error")
}
