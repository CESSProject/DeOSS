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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/CESSProject/cess-oss/pkg/erasure"
	"github.com/CESSProject/cess-oss/pkg/hashtree"
	"github.com/CESSProject/cess-oss/pkg/utils"
	cesskeyring "github.com/CESSProject/go-keyring"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// It is used to authorize users
func (n *Node) putHandle(c *gin.Context) {
	var (
		err error
		acc string
	)

	// token
	tokenString := c.Request.Header.Get(configs.Header_Auth)
	if tokenString == "" {
		//Uld.Sugar().Infof("[%v] head missing token", c.ClientIP())
		c.JSON(403, "NoPermission")
		return
	}

	signKey, err := utils.CalcMD5(n.Confile.GetCtrlPrk())
	if err != nil {
		c.JSON(400, "Invalid.Profile")
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
		c.JSON(403, "NoPermission")
		return
	}

	pkey, err := utils.DecodePublicKeyOfCessAccount(acc)
	if err != nil {
		c.JSON(400, "InvalidParameter.Token")
		return
	}

	putName := c.Param("name")
	if putName == "" {
		//Uld.Sugar().Infof("[%v] no file name", usertoken.Mailbox)
		c.JSON(400, "Invalid.Parameter")
		return
	}

	fileHead, err := c.FormFile("file")
	if err != nil {
		if VerifyBucketName(putName) {
			txHash, err := n.Chain.CreateBucket(pkey, putName)
			if err != nil {
				c.JSON(400, err.Error())
				return
			}
			c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
			return
		}
	}

	// bucket name
	bucketName := c.Request.Header.Get(configs.Header_BucketName)
	if bucketName == "" {
		//Uld.Sugar().Infof("[%v] head missing token", c.ClientIP())
		c.JSON(400, "Invalid.BucketName")
		return
	}

	if !VerifyBucketName(bucketName) {
		c.JSON(400, "Invalid.BucketName")
		return
	}

	//
	grantor, err := n.Chain.GetGrantor(pkey)
	if err != nil {
		c.JSON(400, err.Error())
		return
	}

	account_chain, _ := utils.EncodePublicKeyAsCessAccount(grantor[:])
	account_local, _ := n.Chain.GetCessAccount()
	if account_chain != account_local {
		if err != nil {
			c.JSON(400, "Unauthorized")
			return
		}
	}

	content_length := c.Request.ContentLength
	if content_length <= 0 {
		//Uld.Sugar().Infof("[%v] contentLength <= 0", usertoken.Mailbox)
		c.JSON(400, "Empty file")
		return
	}

	// save file
	file_c, _, err := c.Request.FormFile("file")
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(400, err.Error())
		return
	}

	_, err = os.Stat(n.FileDir)
	if err != nil {
		err = os.MkdirAll(n.FileDir, os.ModeDir)
		if err != nil {
			//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
			c.JSON(500, err.Error())
			return
		}
	}

	// Calc file path
	fpath := filepath.Join(n.FileDir, url.QueryEscape(putName))

	// Create file
	f, err := os.Create(fpath)
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, err.Error())
		return
	}

	// Save file
	buf := make([]byte, 4*1024*1024)
	for {
		n, err := file_c.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			c.JSON(400, err.Error())
			return
		}
		if n == 0 {
			continue
		}
		f.Write(buf[:n])
	}
	f.Close()

	// Calc file state
	fstat, err := os.Stat(fpath)
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, "UnexpectedError")
	}

	// Calc reedsolomon
	chunkPath, datachunkLen, rduchunkLen, err := erasure.ReedSolomon(fpath, fileHead.Size)
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, err.Error())
	}

	if len(chunkPath) != (datachunkLen + rduchunkLen) {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, "ReedSolomon failed")
		c.JSON(500, "UnexpectedError")
	}

	// Calc merkle hash tree
	hTree, err := hashtree.NewHashTree(chunkPath)
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, "UnexpectedError")
	}

	// Merkel root hash
	hashtree := hex.EncodeToString(hTree.MerkleRoot())

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

	userBrief := chain.UserBrief{
		User:        types.NewAccountID(pkey),
		File_name:   types.Bytes(putName),
		Bucket_name: types.Bytes(bucketName),
	}
	// Declaration file
	txhash, err := n.Chain.DeclarationFile(hashtree, userBrief)
	if txhash == "" {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, err.Error())
		return
	}
	go n.task_StoreFile(newChunksPath, hashtree, putName, fstat.Size())

	c.JSON(http.StatusOK, hashtree)
	return

}

func (n *Node) task_StoreFile(fpath []string, fid, fname string, fsize int64) {
	defer func() {
		if err := recover(); err != nil {
			n.Logs.Pnc("error", utils.RecoverError(err))
		}
	}()
	var channel_1 = make(chan uint8, 1)
	//Uld.Sugar().Infof("[%v] Start the file backup management process", fid)
	go n.uploadToStorage(channel_1, fpath, fid, fsize)
	for {
		select {
		case result := <-channel_1:
			if result == 1 {
				go n.uploadToStorage(channel_1, fpath, fid, fsize)
				time.Sleep(time.Second * 6)
			}
			if result == 2 {
				//Uld.Sugar().Infof("[%v] File save successfully", fid)
				return
			}
			if result == 3 {
				//Uld.Sugar().Infof("[%v] File save failed", fid)
				return
			}
		}
	}
}

// Upload files to cess storage system
func (n *Node) uploadToStorage(ch chan uint8, fpath []string, fid string, fsize int64) {
	defer func() {
		err := recover()
		if err != nil {
			ch <- 1
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

	msg := utils.GetRandomcode(16)

	kr, _ := cesskeyring.FromURI(n.Confile.GetCtrlPrk(), cesskeyring.NetSubstrate{})
	// sign message
	sign, err := kr.Sign(kr.SigningContext([]byte(msg)))
	if err != nil {
		ch <- 1
		//Uld.Sugar().Infof("[%v] %v", mailbox, err)
		return
	}

	// Get all scheduler
	schds, err := n.Chain.GetSchedulerList()
	if err != nil {
		ch <- 1
		//Uld.Sugar().Infof("[%v] %v", mailbox, err)
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

		tcpAddr, err := net.ResolveTCPAddr("tcp", wsURL)
		if err != nil {
			//Uld.Sugar().Infof("[%v] %v", mailbox, err)
			continue
		}
		dialer := net.Dialer{Timeout: time.Duration(time.Second * 5)}
		netConn, err := dialer.Dial("tcp", tcpAddr.String())
		if err != nil {
			//Uld.Sugar().Infof("[%v] %v", mailbox, err)
			continue
		}

		conTcp, ok := netConn.(*net.TCPConn)
		if !ok {
			//Uld.Sugar().Infof("[%v] ", err)
			continue
		}

		tcpCon := NewTcp(conTcp)
		srv := NewClient(tcpCon, n.FileDir, existFile)
		// fmt.Println(configs.FileCacheDir)
		// fmt.Println(existFile)
		err = srv.SendFile(fid, fsize, n.Chain.GetPublicKey(), []byte(msg), sign[:])
		if err != nil {
			//Uld.Sugar().Infof("[%v] %v", mailbox, err)
			continue
		}
		ch <- 2
		return
	}
	ch <- 1
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
