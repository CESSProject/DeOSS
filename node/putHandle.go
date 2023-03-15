/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/chain"
	"github.com/CESSProject/DeOSS/pkg/erasure"
	"github.com/CESSProject/DeOSS/pkg/hashtree"
	"github.com/CESSProject/DeOSS/pkg/utils"
	cesskeyring "github.com/CESSProject/go-keyring"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	jwt "github.com/dgrijalva/jwt-go"
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
		err error
		acc string
	)

	// token
	tokenString := c.Request.Header.Get(configs.Header_Auth)
	if tokenString == "" {
		n.Logs.Upfile("error", fmt.Errorf("[%v] missing token", c.ClientIP()))
		c.JSON(400, "InvalidHead.MissToken")
		return
	}

	signKey, err := utils.CalcMD5(n.Confile.GetCtrlPrk())
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(500, "InvalidProfile")
		return
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return signKey, nil
		})

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		acc = claims.Account
	} else {
		n.Logs.Upfile("error", fmt.Errorf("[%v] Token verification failed", c.ClientIP()))
		c.JSON(403, "NoPermission")
		return
	}

	pkey, err := utils.DecodePublicKeyOfCessAccount(acc)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] Account decode failed", c.ClientIP()))
		c.JSON(400, "InvalidHead.Token")
		return
	}

	putName := c.Param("name")
	if putName == "" {
		n.Logs.Upfile("error", fmt.Errorf("[%v] Empty name", c.ClientIP()))
		c.JSON(400, "InvalidParameter.Name")
		return
	}

	// bucket name
	bucketName := c.Request.Header.Get(configs.Header_BucketName)
	if bucketName == "" {
		if VerifyBucketName(putName) {
			txHash, err := n.Chain.CreateBucket(pkey, putName)
			if err != nil {
				n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
				c.JSON(400, err.Error())
				return
			}
			c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
			return
		}
		n.Logs.Upfile("error", fmt.Errorf("[%v] InvalidHead.BucketName", c.ClientIP()))
		c.JSON(400, "InvalidHead.BucketName")
		return
	}

	if !VerifyBucketName(bucketName) {
		n.Logs.Upfile("error", fmt.Errorf("[%v] Wrong BucketName", c.ClientIP()))
		c.JSON(400, "InvalidHead.BucketName")
		return
	}

	//
	grantor, err := n.Chain.GetGrantor(pkey)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(400, "Unauthorized")
		return
	}

	account_chain, _ := utils.EncodePublicKeyAsCessAccount(grantor[:])
	account_local, _ := n.Chain.GetCessAccount()
	if account_chain != account_local {
		if err != nil {
			n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
			c.JSON(400, "Unauthorized")
			return
		}
	}

	content_length := c.Request.ContentLength
	if content_length <= 0 {
		n.Logs.Upfile("error", fmt.Errorf("[%v] Empty file", c.ClientIP()))
		c.JSON(400, "InvalidParameter.EmptyFile")
		return
	}

	_, err = os.Stat(n.FileDir)
	if err != nil {
		err = os.MkdirAll(n.FileDir, configs.DirPermission)
		if err != nil {
			n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
			c.JSON(500, "InternalError")
			return
		}
	}

	// Calc file path
	fpath := filepath.Join(n.FileDir, url.QueryEscape(putName))
	_, err = os.Stat(fpath)
	if err == nil {
		c.JSON(400, "Invalid.DuplicateFileName")
		return
	}

	// save file
	formfile, err := c.FormFile("file")
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(400, "InvalidParameter.FormFile")
		return
	}

	err = c.SaveUploadedFile(formfile, fpath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(400, "InvalidParameter.FormFile")
		return
	}

	// Calc file state
	fstat, err := os.Stat(fpath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(500, "InternalError")
	}

	// Calc reedsolomon
	chunkPath, datachunkLen, rduchunkLen, err := erasure.ReedSolomon(fpath, fstat.Size())
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(500, err.Error())
		return
	}

	if len(chunkPath) != (datachunkLen + rduchunkLen) {
		n.Logs.Upfile("error", fmt.Errorf("[%v] InternalError", c.ClientIP()))
		c.JSON(500, "InternalError")
		return
	}

	// Calc merkle hash tree
	hTree, err := hashtree.NewHashTree(chunkPath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] NewHashTree", c.ClientIP()))
		c.JSON(500, "InternalError")
		return
	}

	// Merkel root hash
	hashtree := hex.EncodeToString(hTree.MerkleRoot())

	// file meta info
	fmeta, err := n.Chain.GetFileMetaInfo(hashtree)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			c.JSON(500, "InternalError")
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
			n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
			c.JSON(400, err.Error())
			return
		}
	} else {
		if string(fmeta.State) == chain.FILE_STATE_ACTIVE {
			c.JSON(200, hashtree)
			return
		}
	}

	// Rename the file and chunks with root hash
	var newChunksPath = make([]string, 0)
	newpath := filepath.Join(n.FileDir, hashtree)
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
	val, _ := json.Marshal(&fileSt)
	n.Cache.Put([]byte(hashtree), val)
	// Record in tracklist
	os.Create(filepath.Join(n.TrackDir, hashtree))
	go n.task_StoreFile(newChunksPath, hashtree, putName, fstat.Size())
	n.Logs.Upfile("info", fmt.Errorf("[%v] Upload success", hashtree))
	c.JSON(http.StatusOK, hashtree)
	return
}

func (n *Node) task_StoreFile(fpath []string, fid, fname string, fsize int64) {
	defer func() {
		if err := recover(); err != nil {
			n.Logs.Pnc("error", utils.RecoverError(err))
		}
	}()
	var channel_1 = make(chan string, 1)

	n.Logs.Upfile("info", fmt.Errorf("[%v] Start the file backup management process", fid))
	go n.uploadToStorage(channel_1, fpath, fid, fsize)
	for {
		select {
		case result := <-channel_1:
			if result == "1" {
				go n.uploadToStorage(channel_1, fpath, fid, fsize)
				time.Sleep(time.Second * 6)
			}
			if len(result) > 1 {
				var fileSt FileStoreInfo
				val_old, _ := n.Cache.Get([]byte(fid))
				json.Unmarshal(val_old, &fileSt)
				fileSt.IsScheduler = true
				fileSt.Scheduler = result
				val_new, _ := json.Marshal(&fileSt)
				n.Cache.Put([]byte(fid), val_new)
				n.Logs.Upfile("info", fmt.Errorf("[%v] File save successfully", fid))
				return
			}
			if result == "3" {
				n.Logs.Upfile("info", fmt.Errorf("[%v] File save failed", fid))
				return
			}
		}
	}
}

// Upload files to cess storage system
func (n *Node) uploadToStorage(ch chan string, fpath []string, fid string, fsize int64) {
	defer func() {
		err := recover()
		if err != nil {
			ch <- "1"
			n.Logs.Pnc("error", utils.RecoverError(err))
		}
	}()

	var existFile = make([]string, 0)
	for i := 0; i < len(fpath); i++ {
		_, err := os.Stat(filepath.Join(n.FileDir, fpath[i]))
		if err != nil {
			continue
		}
		existFile = append(existFile, fpath[i])
	}

	n.Logs.Upfile("info", fmt.Errorf("files:%v", existFile))
	msg := utils.GetRandomcode(16)

	kr, _ := cesskeyring.FromURI(n.Confile.GetCtrlPrk(), cesskeyring.NetSubstrate{})
	// sign message
	sign, err := kr.Sign(kr.SigningContext([]byte(msg)))
	if err != nil {
		ch <- "1"
		return
	}

	// Get all scheduler
	schds, err := n.Chain.GetSchedulerList()
	if err != nil {
		ch <- "1"
		return
	}

	utils.RandSlice(schds)

	for i := 0; i < len(schds); i++ {
		wsURL := fmt.Sprintf("%d.%d.%d.%d:%d",
			schds[i].Ip.Value[0],
			schds[i].Ip.Value[1],
			schds[i].Ip.Value[2],
			schds[i].Ip.Value[3],
			schds[i].Ip.Port,
		)
		n.Logs.Upfile("info", fmt.Errorf("will send to: %v", wsURL))

		conTcp, err := dialTcpServer(wsURL)
		if err != nil {
			n.Logs.Upfile("err", fmt.Errorf("dial %v err: %v", wsURL, err))
			continue
		}

		srv := NewClient(NewTcp(conTcp), n.FileDir, existFile)
		err = srv.SendFile(fid, fsize, n.Chain.GetPublicKey(), []byte(msg), sign[:])
		if err != nil {
			n.Logs.Upfile("err", fmt.Errorf("send to %v err: %v", wsURL, err))
			continue
		}
		ch <- wsURL
		return
	}
	ch <- "1"
}

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

				fmeta, _ := n.Chain.GetFileMetaInfo(v)

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
