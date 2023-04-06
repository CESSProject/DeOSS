/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/chain"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/gin-gonic/gin"
)

type FileStoreInfo struct {
	FileId      string         `json:"file_id"`
	FileState   string         `json:"file_state"`
	Scheduler   string         `json:"scheduler"`
	FileSize    int64          `json:"file_size"`
	IsUpload    bool           `json:"is_upload"`
	IsCheck     bool           `json:"is_check"`
	IsShard     bool           `json:"is_shard"`
	IsScheduler bool           `json:"is_scheduler"`
	Miners      map[int]string `json:"miners,omitempty"`
}

// It is used to authorize users
func (n *Node) putHandle(c *gin.Context) {
	var (
		err      error
		clientIp string
		account  string
		filesize int64
		fpath    string
		filehash string
		roothash string
		httpCode int
		respMsg  = &RespMsg{}
	)

	clientIp = c.ClientIP()
	n.Logs.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, INFO_PutRequest))

	// verify token
	account = n.VerifyToken(c, respMsg)

	// get owner's public key
	pkey, err := utils.DecodePublicKeyOfCessAccount(account)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusBadRequest, ERR_InvalidToken)
		return
	}

	// get parameter name
	putName := c.Param(PUT_ParameterName)
	if putName == "" {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidName))
		c.JSON(http.StatusBadRequest, ERR_InvalidName)
		return
	}

	// bucket name
	bucketName := c.Request.Header.Get(Header_BucketName)

	if bucketName == "" {
		if c.Request.ContentLength > 0 {
			n.Logs.Upfile("err", fmt.Sprintf("[%v] %s", c.ClientIP(), ERR_EmptyBucketName))
			c.JSON(http.StatusBadRequest, ERR_EmptyBucketName)
			return
		}
		txHash, err := n.Cli.CreateBucket(pkey, putName)
		if err != nil {
			n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", c.ClientIP(), err))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
		return
	}

	// upload file operation
	// verify bucket name
	if !VerifyBucketName(bucketName) {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidBucketName))
		c.JSON(http.StatusBadRequest, ERR_InvalidBucketName)
		return
	}

	content_length := c.Request.ContentLength
	if content_length <= 0 {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_EmptyFile))
		c.JSON(400, "InvalidParameter.EmptyFile")
		return
	}

	filesize, filehash, fpath, httpCode, err = n.SaveFormFile(c, account, putName)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		filesize, filehash, fpath, httpCode, err = n.SaveBody(c, account, putName)
		if err != nil {
			n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(httpCode, err)
			return
		}
	}

	filesize = filesize
	filehash = filehash

	roothash, err = n.Cli.PutFile(pkey, fpath, putName, bucketName)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	// Rename the file and chunks with root hash
	// var newChunksPath = make([]string, 0)
	// newpath := filepath.Join(n.FileDir, hashtree)
	// os.Rename(fpath, newpath)
	// if rduchunkLen == 0 {
	// 	newChunksPath = append(newChunksPath, hashtree)
	// } else {
	// 	for i := 0; i < len(chunkPath); i++ {
	// 		var ext = filepath.Ext(chunkPath[i])
	// 		var newchunkpath = filepath.Join(n.FileDir, hashtree+ext)
	// 		os.Rename(chunkPath[i], newchunkpath)
	// 		newChunksPath = append(newChunksPath, hashtree+ext)
	// 	}
	// }

	// var fileSt = FileStoreInfo{
	// 	FileId:      hashtree,
	// 	FileSize:    fstat.Size(),
	// 	FileState:   "pending",
	// 	Scheduler:   "",
	// 	IsUpload:    true,
	// 	IsCheck:     true,
	// 	IsShard:     true,
	// 	IsScheduler: false,
	// 	Miners:      nil,
	// }
	// val, _ := json.Marshal(&fileSt)
	// n.Cache.Put([]byte(hashtree), val)
	// // Record in tracklist
	// os.Create(filepath.Join(n.TrackDir, hashtree))
	// go n.task_StoreFile(newChunksPath, hashtree, putName, fstat.Size())
	// n.Logs.Upfile("info", fmt.Errorf("[%v] Upload success", hashtree))
	c.JSON(http.StatusOK, roothash)
	return
}

// func (n *Node) task_StoreFile(fpath []string, fid, fname string, fsize int64) {
// 	defer func() {
// 		if err := recover(); err != nil {
// 			n.Logs.Pnc("err", utils.RecoverError(err))
// 		}
// 	}()
// 	var channel_1 = make(chan string, 1)

// 	n.Logs.Upfile("info", fmt.Sprintf("[%v] Start the file backup management process", fid))
// 	go n.uploadToStorage(channel_1, fpath, fid, fsize)
// 	for {
// 		select {
// 		case result := <-channel_1:
// 			if result == "1" {
// 				go n.uploadToStorage(channel_1, fpath, fid, fsize)
// 				time.Sleep(time.Second * 6)
// 			}
// 			if len(result) > 1 {
// 				var fileSt FileStoreInfo
// 				val_old, _ := n.Cache.Get([]byte(fid))
// 				json.Unmarshal(val_old, &fileSt)
// 				fileSt.IsScheduler = true
// 				fileSt.Scheduler = result
// 				val_new, _ := json.Marshal(&fileSt)
// 				n.Cache.Put([]byte(fid), val_new)
// 				n.Logs.Upfile("info", fmt.Sprintf("[%v] File save successfully", fid))
// 				return
// 			}
// 			if result == "3" {
// 				n.Logs.Upfile("info", fmt.Sprintf("[%v] File save failed", fid))
// 				return
// 			}
// 		}
// 	}
// }

// // Upload files to cess storage system
// func (n *Node) uploadToStorage(ch chan string, fpath []string, fid string, fsize int64) {
// 	defer func() {
// 		err := recover()
// 		if err != nil {
// 			ch <- "1"
// 			n.Logs.Pnc("error", utils.RecoverError(err))
// 		}
// 	}()

// 	var existFile = make([]string, 0)
// 	for i := 0; i < len(fpath); i++ {
// 		_, err := os.Stat(filepath.Join(n.FileDir, fpath[i]))
// 		if err != nil {
// 			continue
// 		}
// 		existFile = append(existFile, fpath[i])
// 	}

// 	n.Logs.Upfile("info", fmt.Sprintf("files:%v", existFile))
// 	msg := utils.GetRandomcode(16)

// 	kr, _ := cesskeyring.FromURI(n.Confile.GetMnemonic(), cesskeyring.NetSubstrate{})
// 	// sign message
// 	sign, err := kr.Sign(kr.SigningContext([]byte(msg)))
// 	if err != nil {
// 		ch <- "1"
// 		return
// 	}

// 	// Get all scheduler
// 	schds, err := n.Cli.GetSchedulerList()
// 	if err != nil {
// 		ch <- "1"
// 		return
// 	}

// 	utils.RandSlice(schds)

// 	for i := 0; i < len(schds); i++ {
// 		wsURL := fmt.Sprintf("%d.%d.%d.%d:%d",
// 			schds[i].Ip.Value[0],
// 			schds[i].Ip.Value[1],
// 			schds[i].Ip.Value[2],
// 			schds[i].Ip.Value[3],
// 			schds[i].Ip.Port,
// 		)
// 		n.Logs.Upfile("info", fmt.Errorf("will send to: %v", wsURL))

// 		conTcp, err := dialTcpServer(wsURL)
// 		if err != nil {
// 			n.Logs.Upfile("err", fmt.Errorf("dial %v err: %v", wsURL, err))
// 			continue
// 		}

// 		srv := NewClient(NewTcp(conTcp), n.FileDir, existFile)
// 		err = srv.SendFile(fid, fsize, n.Chain.GetPublicKey(), []byte(msg), sign[:])
// 		if err != nil {
// 			n.Logs.Upfile("err", fmt.Errorf("send to %v err: %v", wsURL, err))
// 			continue
// 		}
// 		ch <- wsURL
// 		return
// 	}
// 	ch <- "1"
// }

// Bucket name verification rules
// It can only contain numbers, lowercase letters, special characters (. -)
// And the length is 3-63
// Must start and end with a letter or number
// Must not contain two adjacent points
// Must not be formatted as an IP address
func VerifyBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}

	re, err := regexp.Compile(`^[a-z0-9.-]{3,63}$`)
	if err != nil {
		return false
	}

	if !re.MatchString(name) {
		return false
	}

	if strings.Contains(name, "..") {
		return false
	}

	if byte(name[0]) == byte('.') ||
		byte(name[0]) == byte('-') ||
		byte(name[len(name)-1]) == byte('.') ||
		byte(name[len(name)-1]) == byte('-') {
		return false
	}

	return !utils.IsIPv4(name)
}

func dialTcpServer(address string) (*net.TCPConn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: configs.Tcp_Dial_Timeout}
	netCon, err := dialer.Dial("tcp", tcpAddr.String())
	if err != nil {
		return nil, err
	}
	conTcp, ok := netCon.(*net.TCPConn)
	if !ok {
		return nil, errors.New("network conversion failed")
	}
	return conTcp, nil
}

func (n *Node) TrackFile() {
	var (
		count         uint8
		fileSt        FileStoreInfo
		linuxFileAttr *syscall.Stat_t
	)
	for {
		time.Sleep(time.Second * 10)
		count++
		files, _ := filepath.Glob(filepath.Join(n.TrackDir, "*"))

		if len(files) > 0 {
			for _, v := range files {
				val, _ := n.Cache.Get([]byte(v))
				json.Unmarshal(val, &fileSt)

				fmeta, _ := n.Cli.GetFileMetaInfo(v)

				if fileSt.FileState == chain.FILE_STATE_ACTIVE ||
					string(fmeta.State) == chain.FILE_STATE_ACTIVE {
					os.Remove(filepath.Join(n.TrackDir, v))
					n.Cache.Delete([]byte(v))
					continue
				}

				conTcp, err := dialTcpServer(fileSt.Scheduler)
				if err != nil {
					continue
				}

				NewClient(NewTcp(conTcp), "", nil).SendFileSt(v, n.Cache)
			}
		}

		if count > 60 {
			count = 0
			files, _ = filepath.Glob(filepath.Join(n.FileDir, "*"))
			if len(files) > 0 {
				for _, v := range files {
					fs, err := os.Stat(filepath.Join(n.FileDir, v))
					if err == nil {
						linuxFileAttr = fs.Sys().(*syscall.Stat_t)
						if time.Since(time.Unix(linuxFileAttr.Atim.Sec, 0)).Hours() > configs.FileCacheExpirationTime {
							os.Remove(filepath.Join(n.FileDir, v))
						}
					}
				}
			}
		}
	}
}
