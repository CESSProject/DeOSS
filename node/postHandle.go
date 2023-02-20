/*
   Copyright 2022 CESS scheduler authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package node

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/CESSProject/cess-oss/pkg/db"
	"github.com/CESSProject/cess-oss/pkg/erasure"
	"github.com/CESSProject/cess-oss/pkg/hashtree"
	"github.com/CESSProject/cess-oss/pkg/utils"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"

	"github.com/gin-gonic/gin"
)

type PostLimit struct {
	Day   int   `json:"day"`
	Count uint8 `json:"count"`
}

type RespData struct {
	Msg    string `json:"msg"`
	Msg_cn string `json:"msg_cn"`
	Id     string `json:"id"`
	Link   string `json:"link"`
}

var PostLimitMap map[string]PostLimit

func init() {
	PostLimitMap = make(map[string]PostLimit, 10)
}

// It is used to authorize users
func (n *Node) postHandle(c *gin.Context) {
	var (
		err      error
		respData RespData
		pl       PostLimit
		day      int
		cip      string
		uploaded = new(uint8)
	)
	day = time.Now().Day()
	cip = c.ClientIP()
	defer func(flag *uint8) {
		var totalfiles, totalfailed int64

		if *flag == 0 {
			val, err := n.Cache.Get([]byte(configs.TotalFailedFile))
			if err != nil {
				if err.Error() == db.NotFound.Error() {
					totalfailed = int64(0)
					n.Cache.Put([]byte(configs.TotalFailedFile), utils.Int64ToBytes(totalfailed))
				}
			} else {
				totalfailed = utils.BytesToInt64(val)
				totalfailed++
				n.Cache.Put([]byte(configs.TotalFailedFile), utils.Int64ToBytes(totalfailed))
			}
		} else {
			val, err := n.Cache.Get([]byte(configs.TotalFile))
			if err != nil {
				if err.Error() == db.NotFound.Error() {
					n.Cache.Put([]byte(configs.TotalFile), utils.Int64ToBytes(int64(1)))
					totalfiles = int64(1)
				}
			} else {
				totalfiles = utils.BytesToInt64(val)
				totalfiles++
				n.Cache.Put([]byte(configs.TotalFile), utils.Int64ToBytes(int64(totalfiles)))
			}
		}
		n.Logs.Record(fmt.Errorf("%v %d %d %d", cip, *flag, totalfiles, totalfailed))
	}(uploaded)

	val, err := n.Cache.Get([]byte(cip))
	if err == nil {
		err = json.Unmarshal(val, &pl)
		if err != nil {
			n.Cache.Delete([]byte(cip))
		} else {
			if pl.Day == day {
				if pl.Count >= configs.UploadCountPerDay {
					respData.Msg = fmt.Sprintf("Today's %d times have been used up", configs.UploadCountPerDay)
					respData.Msg_cn = fmt.Sprintf("今天的%d次已用完", configs.UploadCountPerDay)
					c.JSON(400, respData)
					return
				}
			} else {
				pl.Day = day
				pl.Count = 0
				val, err := json.Marshal(&pl)
				if err == nil {
					n.Cache.Put([]byte(cip), val)
				}
			}
		}
	}

	putName := c.Param("name")
	if putName == "" {
		n.Logs.Upfile("error", fmt.Errorf("[%v] Empty name", cip))
		respData.Msg = "File name cannot be empty"
		respData.Msg_cn = "文件名不能为空"
		c.JSON(400, respData)
		return
	}
	fext := filepath.Ext(putName)

	// bucket name
	bucketName := configs.SelfBucketName

	content_length := c.Request.ContentLength
	if content_length > configs.MaxFileSize {
		n.Logs.Upfile("error", fmt.Errorf("[%v] Empty file", cip))
		respData.Msg = fmt.Sprintf("Cannot upload the file exceeding %dMB", configs.MaxFileSize/configs.SIZE_1MiB)
		respData.Msg_cn = fmt.Sprintf("无法上传超过%dMB的文件", configs.MaxFileSize/configs.SIZE_1MiB)
		c.JSON(400, respData)
		return
	}

	_, err = os.Stat(n.FileDir)
	if err != nil {
		err = os.MkdirAll(n.FileDir, configs.DirPermission)
		if err != nil {
			n.Logs.Upfile("error", fmt.Errorf("[%v] %v", cip, err))
			respData.Msg = "Sorry, there was an error uploading your file, please try again"
			respData.Msg_cn = "文件上传遇到问题，请重试"
			c.JSON(500, respData)
			return
		}
	}

	// Calc file path
	fpath := ""
	for {
		fpath = filepath.Join(n.FileDir, fmt.Sprintf("%s_%v", url.QueryEscape(putName), time.Now().UnixNano()))
		_, err = os.Stat(fpath)
		if err != nil {
			break
		}
	}
	defer os.Remove(fpath)

	// save file
	formfile, err := c.FormFile("file")
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", cip, err))
		respData.Msg = "Sorry, there was an error uploading your file, please try again"
		respData.Msg_cn = "文件上传遇到问题，请重试"
		c.JSON(400, respData)
		return
	}

	err = c.SaveUploadedFile(formfile, fpath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", cip, err))
		respData.Msg = "Sorry, there was an error uploading your file, please try again"
		respData.Msg_cn = "文件上传遇到问题，请重试"
		c.JSON(400, respData)
		return
	}

	// Calc file state
	fstat, err := os.Stat(fpath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", cip, err))
		respData.Msg = "Sorry, there was an error uploading your file, please try again"
		respData.Msg_cn = "文件上传遇到问题，请重试"
		c.JSON(500, respData)
		return
	}

	if fext == "" {
		fext, err = utils.GetFileType(fpath)
		if err != nil {
			n.Logs.Upfile("error", fmt.Errorf("[%v] %v", cip, err))
			respData.Msg = "The file name format is invalid"
			respData.Msg_cn = "文件名的格式不合法"
			c.JSON(400, respData)
			return
		}
	}

	if !strings.ContainsAny(fext, ".") {
		fext = fmt.Sprintf(".%s", fext)
	}

	// Calc reedsolomon
	chunkPath, datachunkLen, rduchunkLen, err := erasure.ReedSolomon(fpath, fstat.Size())
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", cip, err))
		respData.Msg = "Sorry, there was an error uploading your file, please try again"
		respData.Msg_cn = "文件上传遇到问题，请重试"
		c.JSON(500, respData)
		return
	}

	if len(chunkPath) != (datachunkLen + rduchunkLen) {
		n.Logs.Upfile("error", fmt.Errorf("[%v] InternalError", cip))
		respData.Msg = "Sorry, there was an error uploading your file, please try again"
		respData.Msg_cn = "文件上传遇到问题，请重试"
		c.JSON(500, respData)
		return
	}

	// Calc merkle hash tree
	hTree, err := hashtree.NewHashTree(chunkPath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] NewHashTree", cip))
		respData.Msg = "Sorry, there was an error uploading your file, please try again"
		respData.Msg_cn = "文件上传遇到问题，请重试"
		c.JSON(500, respData)
		return
	}

	// Merkel root hash
	hashtree := hex.EncodeToString(hTree.MerkleRoot())
	newpath := filepath.Join(n.FileDir, hashtree)
	_, err = os.Stat(newpath)
	if err == nil {
		respData.Msg = "ok"
		respData.Id = hashtree
		respData.Link = fmt.Sprintf("%s/%s%s", configs.PublicOssDomainName, hashtree, fext)
		*uploaded = 1
		c.JSON(200, respData)
		return
	}

	pkey, _ := utils.DecodePublicKeyOfCessAccount(configs.SelfAccount)

	// file meta info
	fmeta, err := n.Chain.GetFileMetaInfo(hashtree)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			//respData.Msg = "An exception occurred while accessing cess chain, please try again"
			respData.Msg = "Sorry, there was an error uploading your file, please try again"
			respData.Msg_cn = "文件上传遇到问题，请重试"
			c.JSON(400, respData)
			return
		}
		userBrief := chain.UserBrief{
			User:        types.NewAccountID(pkey),
			File_name:   types.Bytes(putName),
			Bucket_name: types.Bytes(bucketName),
		}
		// Declaration file
		txhash, err := n.Chain.DeclarationFile(hashtree, userBrief)
		if err != nil || txhash == "" {
			n.Logs.Upfile("error", fmt.Errorf("[%v] %v", cip, err))
			//respData.Msg = "Transaction failed, please contact the administrator"
			respData.Msg = "Sorry, there was an error uploading your file, please try again"
			respData.Msg_cn = "文件上传遇到问题，请重试"
			c.JSON(500, respData)
			return
		}
	} else {
		if string(fmeta.State) == chain.FILE_STATE_ACTIVE {
			respData.Msg = "ok"
			respData.Id = hashtree
			respData.Link = fmt.Sprintf("%s/%s%s", configs.PublicOssDomainName, hashtree, fext)
			c.JSON(200, respData)
			*uploaded = 1
			return
		}
	}

	// Rename the file and chunks with root hash
	var newChunksPath = make([]string, 0)

	os.Rename(fpath, newpath)
	if rduchunkLen == 0 {
		newChunksPath = append(newChunksPath, hashtree)
	} else {
		for i := 0; i < len(chunkPath); i++ {
			var ext = filepath.Ext(chunkPath[i])
			var newchunkpath = filepath.Join(n.FileDir, hashtree+ext)
			os.Rename(chunkPath[i], newchunkpath)
			newChunksPath = append(newChunksPath, hashtree+ext)
		}
	}

	var fileSt = FileStoreInfo{
		FileId:      hashtree,
		FileSize:    fstat.Size(),
		FileState:   "pending",
		Scheduler:   "",
		IsUpload:    true,
		IsCheck:     true,
		IsShard:     true,
		IsScheduler: false,
		Miners:      nil,
	}
	val, _ = json.Marshal(&fileSt)
	n.Cache.Put([]byte(hashtree), val)
	// Record in tracklist
	os.Create(filepath.Join(n.TrackDir, hashtree))
	go n.task_StoreFile(newChunksPath, hashtree, putName, fstat.Size())
	n.Logs.Upfile("info", fmt.Errorf("[%v] Upload success", hashtree))
	respData.Msg = "ok"
	respData.Id = hashtree
	respData.Link = fmt.Sprintf("%s/%s%s", configs.PublicOssDomainName, hashtree, fext)
	c.JSON(http.StatusOK, respData)
	*uploaded = 1
	val, err = n.Cache.Get([]byte(cip))
	if err != nil {
		pl.Day = day
		pl.Count = 1
		val, err = json.Marshal(&pl)
		if err == nil {
			n.Cache.Put([]byte(cip), val)
		}
		return
	}

	err = json.Unmarshal(val, &pl)
	if err != nil {
		n.Cache.Delete([]byte(cip))
		pl.Day = day
		pl.Count = 2
	} else {
		if pl.Day != day {
			pl.Day = day
			pl.Count = 1
		} else {
			pl.Count++
		}
	}
	val, err = json.Marshal(&pl)
	if err == nil {
		n.Cache.Put([]byte(cip), val)
	}

	return
}
