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
	"syscall"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/sdk-go/core/pattern"
	sutils "github.com/CESSProject/sdk-go/core/utils"
	"github.com/gin-gonic/gin"
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
		c.JSON(400, "InvalidParameter.EmptyFile")
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

	segmentInfo, roothash, err := n.ProcessingData(fpath)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	roothashpath := filepath.Join(n.GetDirs().FileDir, roothash)
	_, err = os.Stat(roothashpath)
	if err == nil {
		c.JSON(http.StatusOK, roothash)
		return
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

func (n *Node) TrackFile() {
	var (
		count         uint8
		txhash        string
		roothash      string
		recordFile    RecordInfo
		storageorder  pattern.StorageOrder
		linuxFileAttr *syscall.Stat_t
	)
	for {
		files, _ := filepath.Glob(filepath.Join(n.Workspace(), configs.Track, "/*"))
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
							os.Remove(files[i])
							for _, segment := range meta.SegmentList {
								os.Remove(filepath.Join(n.Workspace(), configs.File, string(segment.Hash[:])))
								for _, fragment := range segment.FragmentList {
									os.Remove(filepath.Join(n.Workspace(), configs.File, string(fragment.Hash[:])))
								}
							}
						}
					}
					continue
				}
			}

			b, err = os.ReadFile(files[i])
			if err != nil {
				n.Upfile("info", fmt.Sprintf("[%s] File backup failed: %v", roothash, err))
				os.Remove(files[i])
				continue
			}

			err = json.Unmarshal(b, &recordFile)
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

			count, err = n.PutFile(recordFile.Owner, recordFile.SegmentInfo, roothash, recordFile.Filename, recordFile.Buckname)
			if err != nil {
				n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
				continue
			}

			n.Upfile("info", fmt.Sprintf("[%s] File [%s] backup suc", txhash, roothash))

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
		files, _ = filepath.Glob(filepath.Join(n.Workspace(), configs.File, "/*"))
		for _, v := range files {
			fs, err := os.Stat(v)
			if err == nil {
				linuxFileAttr = fs.Sys().(*syscall.Stat_t)
				if time.Since(time.Unix(linuxFileAttr.Atim.Sec, 0)).Hours() > configs.FileCacheExpirationTime {
					os.Remove(v)
				}
			}
		}

		time.Sleep(configs.BlockInterval)
	}
}
