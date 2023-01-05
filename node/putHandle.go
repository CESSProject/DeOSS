/*
   Copyright 2022 CESS (Cumulus Encrypted Storage System) authors

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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/CESSProject/cess-oss/pkg/client"
	"github.com/CESSProject/cess-oss/pkg/hashtree"
	"github.com/CESSProject/cess-oss/pkg/utils"
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
		n.Logs.Upfile("error", fmt.Errorf("[%v] missing token", c.ClientIP()))
		c.JSON(400, "InvalidHead.MissToken")
		return
	}

	signKey, err := utils.CalcMD5(n.Cfile.GetCtrlPrk())
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
			txHash, err := n.Chn.CreateBucket(pkey, putName)
			if err != nil {
				n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
				c.JSON(400, err.Error())
				return
			}
			c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
			return
		}
		c.JSON(400, "InvalidHead.BucketName")
		return
	}

	if !VerifyBucketName(bucketName) {
		n.Logs.Upfile("error", fmt.Errorf("[%v] Wrong BucketName", c.ClientIP()))
		c.JSON(400, "InvalidHead.BucketName")
		return
	}

	// Digest
	digest := c.Request.Header.Get(configs.Header_Digest)
	if digest != "" {
		fmeta, err := n.Chn.GetFileMetaInfo(digest)
		if err == nil {
			if string(fmeta.State) == chain.FILE_STATE_ACTIVE {
				c.JSON(http.StatusOK, digest)
				return
			}
		}

		val, err := n.Cach.Get([]byte(digest))
		if err == nil {
			var fileSt client.StorageProgress
			err = json.Unmarshal(val, &fileSt)
			if err != nil {
				n.Logs.Upfile("info", fmt.Errorf("[%v] Data has been uploaded", string(val)))
				c.JSON(http.StatusOK, string(val))
				return
			}
			n.Logs.Upfile("info", fmt.Errorf("[%v] Data is being backed up", fileSt.FileId))
			c.JSON(http.StatusOK, fileSt.FileId)
			return
		}
	}

	// Grantor
	grantor, err := n.Chn.GetGrantor(pkey)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		if err.Error() == chain.ERR_Empty {
			c.JSON(400, "Unauthorized")
			return
		}
		c.JSON(500, "InternalError")
		return
	}
	account_chain, _ := utils.EncodePublicKeyAsCessAccount(grantor[:])
	account_local, _ := n.Chn.GetCessAccount()
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
		os.Chmod(n.FileDir, configs.DirPermission)
	}

	// Calc file path
	fpath := filepath.Join(n.FileDir, url.QueryEscape(putName))
	_, err = os.Stat(fpath)
	if err == nil {
		c.JSON(400, "Invalid.DuplicateFileName")
		return
	}

	// Create file
	f, err := os.Create(fpath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(500, "InternalError")
		return
	}
	defer os.Remove(fpath)

	// save file
	file_c, _, err := c.Request.FormFile("file")
	if err != nil {
		f.Close()
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(400, "InvalidParameter.FormFile")
		return
	}

	// Save file
	buf := make([]byte, 4*1024*1024)
	for {
		num, err := file_c.Read(buf)
		if err != nil && err != io.EOF {
			n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
			c.JSON(400, "InvalidParameter.File")
			return
		}
		if num == 0 {
			break
		}
		f.Write(buf[:num])
		f.Sync()
	}

	f.Close()

	fsata, err := os.Stat(fpath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(500, "InternalError")
		return
	}

	hash256, err := utils.CalcPathSHA256(fpath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
		c.JSON(500, "InternalError")
		return
	}

	chunkPath, count, lastSize, err := Chunking(fpath)
	fmt.Println(count)
	fmt.Println(chunkPath)
	// Calc merkle hash tree
	hTree, err := hashtree.NewHashTree(chunkPath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Errorf("[%v] NewHashTree", c.ClientIP()))
		c.JSON(500, "InternalError")
	}

	// Merkel root hash
	hashtree := hex.EncodeToString(hTree.MerkleRoot())

	// for _, v := range hTree.Leafs {
	// 	fmt.Println(hex.EncodeToString(v.Hash))
	// }

	n.Cach.Put([]byte(Key_Digest+hash256), []byte(hashtree))
	var slicesHash string
	for i := 0; i < len(chunkPath); i++ {
		slicesHash += filepath.Base(chunkPath[i])
		if (i + 1) < len(chunkPath) {
			slicesHash += "#"
		}
	}
	fmt.Println(slicesHash)
	n.Cach.Put([]byte(Key_Slices+hashtree), []byte(slicesHash))

	// file meta info
	_, err = n.Chn.GetFileMetaInfo(hashtree)
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
		txhash, err := n.Chn.DeclarationFile(hashtree, uint64(fsata.Size()), chunkPath, userBrief)
		if err != nil || txhash == "" {
			n.Logs.Upfile("error", fmt.Errorf("[%v] %v", c.ClientIP(), err))
			c.JSON(400, err.Error())
			return
		}
	} else {
		c.JSON(200, hashtree)
		return
	}

	var fileSt = client.StorageProgress{
		FileId:      hashtree,
		FileSize:    fsata.Size(),
		FileState:   chain.FILE_STATE_PENDING,
		Scheduler:   "",
		IsUpload:    true,
		IsCheck:     true,
		IsShard:     true,
		IsScheduler: false,
	}
	val, _ := json.Marshal(&fileSt)
	n.Cach.Put([]byte(hashtree), val)
	os.Create(filepath.Join(n.TrackDir, hashtree))
	go n.task_StoreFile(chunkPath, hashtree, lastSize)
	n.Logs.Upfile("info", fmt.Errorf("[%v] Upload success", hashtree))
	c.JSON(http.StatusOK, hashtree)
	return
}

func (n *Node) task_StoreFile(fpath []string, fid string, lastsize int64) {
	defer func() {
		if err := recover(); err != nil {
			n.Logs.Pnc("error", utils.RecoverError(err))
		}
	}()
	var ch_Scheduler = make(chan string, 1)

	n.Logs.Upfile("info", fmt.Errorf("[%v] Start the file backup management process", fid))
	go n.uploadToStorage(ch_Scheduler, fpath, fid, lastsize)
	for {
		select {
		case result := <-ch_Scheduler:
			if result == ERR_RETRY {
				go n.uploadToStorage(ch_Scheduler, fpath, fid, lastsize)
				time.Sleep(time.Second * 6)
			} else if _, err := utils.DecodePublicKeyOfCessAccount(result); err == nil {
				var fileSt client.StorageProgress
				val_old, _ := n.Cach.Get([]byte(fid))
				json.Unmarshal(val_old, &fileSt)
				fileSt.IsScheduler = true
				fileSt.Scheduler = result
				val_new, _ := json.Marshal(&fileSt)
				n.Cach.Put([]byte(fid), val_new)
				n.Logs.Upfile("info", fmt.Errorf("[%v] File save successfully", fid))
				return
			} else {
				go n.uploadToStorage(ch_Scheduler, fpath, fid, lastsize)
				time.Sleep(time.Second * 6)
			}
		}
	}
}

// Upload files to cess storage system
func (n *Node) uploadToStorage(ch chan string, fpath []string, fid string, lastsize int64) {
	defer func() {
		err := recover()
		if err != nil {
			ch <- ERR_RETRY
			n.Logs.Pnc("error", utils.RecoverError(err))
		}
	}()

	n.Logs.Upfile("info", fmt.Errorf("files:%v", fpath))

	// Get all scheduler
	schds, err := n.Chn.GetSchedulerList()
	if err != nil {
		ch <- ERR_RETRY
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

		token, err := client.AuthReq(conTcp, n.Cfile.GetCtrlPrk())
		if err != nil {
			conTcp.Close()
			n.Logs.Upfile("err", fmt.Errorf("dial %v err: %v", wsURL, err))
			continue
		}

		var fsize int64
		var lastfile bool
		for j := 0; j < len(fpath); j++ {
			if (j + 1) == len(fpath) {
				fsize = lastsize
				lastfile = true
			} else {
				fsize = configs.SIZE_SLICE
				lastfile = false
			}
			err = client.FileReq(conTcp, token, fid, fpath[j], fsize, lastfile)
			if err != nil {
				n.Logs.Upfile("err", err)
				conTcp.Close()
				break
			}
			fmt.Println("file send succ!")
		}
		if err != nil {
			continue
		}
		fmt.Println("file send succ2!")
		acc, _ := utils.EncodePublicKeyAsCessAccount(schds[i].ControllerUser[:])
		ch <- acc
		return
	}
	ch <- ERR_RETRY
}

// Bucket name verification rules
// It can only contain numbers, lowercase letters, special characters (. -)
// And the length is 3-63
// Must start and end with a letter or number
// Must not contain two adjacent points
// Must not be formatted as an IP address
func VerifyBucketName(name string) bool {
	if len(name) < configs.MinBucketName || len(name) > configs.MaxBucketName {
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
		conTcp.Close()
		return nil, errors.New("network conversion failed")
	}
	return conTcp, nil
}

func (n *Node) TrackFile() {
	var (
		count         uint8
		ip            string
		acc           string
		fileSt        client.StorageProgress
		linuxFileAttr *syscall.Stat_t
	)

	for {
		time.Sleep(time.Second * 10)
		count++
		files, _ := filepath.Glob(filepath.Join(n.TrackDir, "*"))

		if len(files) > 0 {
			for _, v := range files {
				sches, err := n.Chn.GetSchedulerList()
				if err != nil {
					continue
				}

				val, _ := n.Cach.Get([]byte(v))
				json.Unmarshal(val, &fileSt)

				fmeta, _ := n.Chn.GetFileMetaInfo(v)

				if fileSt.FileState == chain.FILE_STATE_ACTIVE ||
					string(fmeta.State) == chain.FILE_STATE_ACTIVE {
					os.Remove(filepath.Join(n.TrackDir, v))
					n.Cach.Delete([]byte(v))
					continue
				}
				ip = ""
				for i := 0; i > len(sches); i++ {
					acc, _ = utils.EncodePublicKeyAsCessAccount(sches[i].ControllerUser[:])
					if acc == fileSt.Scheduler {
						ip = fmt.Sprintf("%d.%d.%d.%d:%d",
							sches[i].Ip.Value[0],
							sches[i].Ip.Value[1],
							sches[i].Ip.Value[2],
							sches[i].Ip.Value[3],
							sches[i].Ip.Port)
					}
				}

				if ip == "" {
					continue
				}

				conTcp, err := dialTcpServer(ip)
				if err != nil {
					continue
				}

				val, err = client.ProgressReq(conTcp, v)
				conTcp.Close()
				if err != nil {
					continue
				}
				n.Cach.Put([]byte(v), val)
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

func Chunking(fpath string) ([]string, int, int64, error) {
	fstat, err := os.Stat(fpath)
	if err != nil {
		return nil, 0, 0, err
	}
	if fstat.IsDir() {
		return nil, 0, 0, fmt.Errorf("Not a file")
	}

	count := fstat.Size() / (configs.SIZE_1MiB * 512)

	lastSize := fstat.Size() % (configs.SIZE_1MiB * 512)
	if lastSize > 0 {
		count += 1
	}

	rtnList := make([]string, count)

	appendSize := configs.SIZE_1MiB*512 - lastSize

	fbase, err := os.Open(fpath)
	if err != nil {
		return nil, 0, 0, err
	}
	buf := make([]byte, configs.SIZE_1MiB*512)
	appendSizeBuf := make([]byte, appendSize)
	baseDir := filepath.Dir(fpath)
	for i := int64(0); i < count; i++ {
		fbase.Seek(i*configs.SIZE_1MiB*512, 0)
		n, err := fbase.Read(buf)
		if err != nil && err != io.EOF {
			return nil, 0, 0, err
		}

		tempPath := fpath + fmt.Sprintf("%d", i)
		fs, err := os.Create(tempPath)
		if err != nil {
			return nil, 0, 0, err
		}

		if (i + 1) < count {
			if n != configs.SIZE_1MiB*512 {
				fs.Close()
				return nil, 0, 0, err
			}
			_, err = fs.Write(buf[:n])
			if err != nil {
				fs.Close()
				return nil, 0, 0, err
			}
		} else {
			if int64(n) != lastSize {
				fs.Close()
				return nil, 0, 0, err
			}
			_, err = fs.Write(buf[:n])
			if err != nil {
				fs.Close()
				return nil, 0, 0, err
			}
			_, err = fs.Write(appendSizeBuf)
			if err != nil {
				fs.Close()
				return nil, 0, 0, err
			}
		}
		err = fs.Sync()
		if err != nil {
			fs.Close()
			return nil, 0, 0, err
		}
		fs.Close()

		rtnList[i], err = utils.CalcPathSHA256(tempPath)
		if err != nil {
			return nil, 0, 0, err
		}
		os.Rename(tempPath, fmt.Sprintf("%v/%v", baseDir, rtnList[i]))
		rtnList[i] = fmt.Sprintf("%v/%v", baseDir, rtnList[i])
	}

	return rtnList, int(count), lastSize, nil
}
