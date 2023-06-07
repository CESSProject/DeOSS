/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/sdk-go/core/pattern"
	sutils "github.com/CESSProject/sdk-go/core/utils"
	"github.com/gin-gonic/gin"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
)

type RecordInfo struct {
	SegmentInfo []pattern.SegmentDataInfo `json:"segmentInfo"`
	Owner       []byte                    `json:"owner"`
	Roothash    string                    `json:"roothash"`
	Filename    string                    `json:"filename"`
	Buckname    string                    `json:"buckname"`
	Putflag     bool                      `json:"putflag"`
	Count       uint8                     `json:"count"`
}

// It is used to authorize users
func (n *Node) putHandle(c *gin.Context) {
	var (
		err      error
		clientIp string
		account  string
		fpath    string
		roothash string
		httpCode int
		respMsg  = &RespMsg{}
	)

	clientIp = c.ClientIP()
	n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, INFO_PutRequest))

	// verify token
	account, pkey, err := n.VerifyToken(c, respMsg)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(respMsg.Code, respMsg.Err)
		return
	}

	// get parameter name
	putName := c.Param(PUT_ParameterName)
	if putName == "" {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidName))
		c.JSON(http.StatusBadRequest, ERR_InvalidName)
		return
	}

	// bucket name
	bucketName := c.Request.Header.Get(Header_BucketName)

	if bucketName == "" {
		if c.Request.ContentLength > 0 {
			n.Upfile("err", fmt.Sprintf("[%v] %s", c.ClientIP(), ERR_EmptyBucketName))
			c.JSON(http.StatusBadRequest, ERR_EmptyBucketName)
			return
		}
		if !sutils.CheckBucketName(putName) {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidBucketName))
			c.JSON(http.StatusBadRequest, ERR_InvalidBucketName)
			return
		}
		txHash, err := n.CreateBucket(pkey, putName)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %v", c.ClientIP(), err))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
		return
	}

	// upload file operation
	// verify bucket name
	if !sutils.CheckBucketName(bucketName) {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidBucketName))
		c.JSON(http.StatusBadRequest, ERR_InvalidBucketName)
		return
	}

	content_length := c.Request.ContentLength
	if content_length <= 0 {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_EmptyFile))
		c.JSON(http.StatusBadRequest, ERR_EmptyFile)
		return
	}

	fpath, httpCode, err = n.SaveFormFile(c, account, putName)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		fpath, httpCode, err = n.SaveBody(c, account, putName)
		if err != nil {
			n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(httpCode, err)
			return
		}
	}
	defer os.Remove(fpath)

	fstat, err := os.Stat(fpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	userInfo, err := n.QueryUserSpaceSt(pkey)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	blockheight, err := n.QueryBlockHeight("")
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	if userInfo.Deadline <= blockheight {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_SpaceExpired))
		c.JSON(http.StatusForbidden, ERR_SpaceExpired)
		return
	}

	usedSpace := fstat.Size() * 15 / 10
	remainingSpace, err := strconv.ParseUint(userInfo.RemainingSpace, 10, 64)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	if usedSpace > int64(remainingSpace) {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_NotEnoughSpace))
		c.JSON(http.StatusForbidden, ERR_NotEnoughSpace)
		return
	}

	segmentInfo, roothash, err := n.ProcessingData(fpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	roothashpath := filepath.Join(n.GetDirs().FileDir, roothash)
	_, err = os.Stat(roothashpath)
	if err == nil {
		_, err = os.Stat(filepath.Join(n.TrackDir, roothash))
		if err == nil {
			c.JSON(http.StatusOK, roothash)
			return
		}
	}

	err = os.Rename(fpath, roothashpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	var recordInfo = &RecordInfo{
		SegmentInfo: segmentInfo,
		Owner:       pkey,
		Roothash:    roothash,
		Filename:    putName,
		Buckname:    bucketName,
		Putflag:     false,
	}

	f, err := os.Create(filepath.Join(n.TrackDir, roothash))
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	b, err := json.Marshal(recordInfo)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	f.Write(b)
	err = f.Sync()
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, roothash)
	return
}

func (n *Node) trackFile(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	var (
		count         uint8
		roothash      string
		ownerAcc      string
		recordFile    RecordInfo
		storageorder  pattern.StorageOrder
		linuxFileAttr *syscall.Stat_t
	)

	for {
		time.Sleep(pattern.BlockInterval)
		files, _ := filepath.Glob(fmt.Sprintf("%s/*", n.TrackDir))
		for i := 0; i < len(files); i++ {
			roothash = filepath.Base(files[i])
			b, err := n.Cache.Get([]byte("transfer:" + roothash))
			if err == nil {
				storageorder, err = n.QueryStorageOrder(roothash)
				if err != nil {
					if err.Error() != pattern.ERR_Empty {
						n.Upfile("err", err.Error())
						continue
					}

					meta, err := n.QueryFileMetadata(roothash)
					if err != nil {
						if err.Error() != pattern.ERR_Empty {
							n.Upfile("err", err.Error())
							continue
						}
					} else {
						if meta.State == Active {
							recordFile, err = parseRecordInfoFromFile(files[i])
							if err == nil {
								ownerAcc, err = utils.EncodePublicKeyAsCessAccount(recordFile.Owner)
								if err == nil {
									for _, segment := range meta.SegmentList {
										os.Remove(filepath.Join(n.GetDirs().FileDir, ownerAcc, string(segment.Hash[:])))
										for _, fragment := range segment.FragmentList {
											os.Remove(filepath.Join(n.GetDirs().FileDir, ownerAcc, string(fragment.Hash[:])))
										}
									}
								}
							}
							os.Remove(files[i])
						}
					}
					continue
				}
			}

			recordFile, err = parseRecordInfoFromFile(files[i])
			if err != nil {
				n.Upfile("info", fmt.Sprintf("[%s] File backup failed: %v", roothash, err))
				os.Remove(files[i])
				continue
			}

			if roothash != recordFile.Roothash {
				n.Upfile("info", fmt.Sprintf("[%s] File backup failed: fid is not equal", roothash))
				os.Remove(files[i])
				continue
			}

			if recordFile.Putflag {
				if storageorder.AssignedMiner != nil {
					if uint8(storageorder.Count) == recordFile.Count {
						continue
					}
				}
			}

			count, err = n.backupFiles(recordFile.Owner, recordFile.SegmentInfo, roothash, recordFile.Filename, recordFile.Buckname)
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
				continue
			}

			n.Upfile("info", fmt.Sprintf("File [%s] backup suc", roothash))

			recordFile.Putflag = true
			recordFile.Count = count
			b, err = json.Marshal(&recordFile)
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
				continue
			}

			f, err := os.OpenFile(filepath.Join(n.TrackDir, roothash), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
				continue
			}
			_, err = f.Write(b)
			if err != nil {
				f.Close()
				n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
				continue
			}

			err = f.Sync()
			if err != nil {
				f.Close()
				n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
				continue
			}
			f.Close()
			n.Cache.Put([]byte("transfer:"+roothash), []byte(fmt.Sprintf("%v", count)))
		}

		// Delete files that have not been accessed for more than 30 days
		files, _ = filepath.Glob(filepath.Join(n.GetDirs().FileDir, "/*"))
		for _, v := range files {
			fs, err := os.Stat(v)
			if err == nil {
				linuxFileAttr = fs.Sys().(*syscall.Stat_t)
				if time.Since(time.Unix(linuxFileAttr.Atim.Sec, 0)).Hours() > configs.FileCacheExpirationTime {
					os.Remove(v)
				}
			}
		}
	}
}

func (n *Node) backupFiles(owner []byte, segmentInfo []pattern.SegmentDataInfo, roothash, filename, bucketname string) (uint8, error) {
	var err error
	var storageOrder pattern.StorageOrder

	_, err = n.QueryFileMetadata(roothash)
	if err == nil {
		return 0, nil
	}

	for i := 0; i < 3; i++ {
		storageOrder, err = n.QueryStorageOrder(roothash)
		if err != nil {
			if err.Error() == pattern.ERR_Empty {
				_, err = n.GenerateStorageOrder(roothash, segmentInfo, owner, filename, bucketname)
				if err != nil {
					return 0, err
				}
			}
			time.Sleep(pattern.BlockInterval)
			continue
		}
		break
	}
	if err != nil {
		return 0, err
	}

	// store fragment to storage
	err = n.storageData(roothash, segmentInfo, storageOrder.AssignedMiner)
	if err != nil {
		return 0, err
	}
	return uint8(storageOrder.Count), nil
}

func (n *Node) storageData(roothash string, segment []pattern.SegmentDataInfo, minerTaskList []pattern.MinerTaskList) error {
	var err error

	// query all assigned miner multiaddr
	peerids, err := n.QueryAssignedMiner(minerTaskList)
	if err != nil {
		return err
	}

	basedir := filepath.Dir(segment[0].FragmentHash[0])
	for i := 0; i < len(peerids); i++ {
		if !n.Has(peerids[i]) {
			return fmt.Errorf("No allocated storage node found: %s", peerids[i])
		}

		id, _ := peer.Decode(peerids[i])
		for j := 0; j < len(minerTaskList[i].Hash); j++ {
			err = n.WriteFileAction(id, roothash, filepath.Join(basedir, string(minerTaskList[i].Hash[j][:])))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (n *Node) QueryAssignedMiner(minerTaskList []pattern.MinerTaskList) ([]string, error) {
	var peerids = make([]string, len(minerTaskList))
	for i := 0; i < len(minerTaskList); i++ {
		minerInfo, err := n.QueryStorageMiner(minerTaskList[i].Account[:])
		if err != nil {
			return peerids, err
		}
		peerids[i] = base58.Encode([]byte(string(minerInfo.PeerId[:])))
	}
	return peerids, nil
}

func parseRecordInfoFromFile(file string) (RecordInfo, error) {
	var result RecordInfo
	b, err := os.ReadFile(file)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(b, &result)
	return result, err
}
