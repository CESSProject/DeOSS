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
	"github.com/gin-gonic/gin"
)

// putHandle is used to create buckets and upload files
func (n *Node) putHandle(c *gin.Context) {
	var (
		err                 error
		httpCode            int
		filesize            int64
		fpath               string
		filehash            string
		roothash            string
		putName             string
		clientIp            string
		account             string
		txHash              string
		bucketName          string
		userBrief           chain.UserBrief
		fileStorageProgress client.StorageProgress
	)

	clientIp = c.ClientIP()
	n.Logs.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, INFO_PutRequest))

	// verify token
	httpCode, account, err = n.VerifyToken(c)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(httpCode, err)
		return
	}

	// get owner's public key
	pkey, err := utils.DecodePublicKeyOfCessAccount(account)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusBadRequest, ERR_InvalidToken)
		return
	}

	// get parameter name
	putName = c.Param(PUT_ParameterName)
	if putName == "" {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidName))
		c.JSON(http.StatusBadRequest, ERR_InvalidName)
		return
	}

	// get bucket name
	bucketName = c.Request.Header.Get(Header_BucketName)

	// create bucket operation
	if bucketName == "" {
		httpCode, err = n.PutBucket(putName, pkey)
		if err != nil {
			n.Logs.Upfile("err", err.Error())
		}
		c.JSON(httpCode, err)
		return
	}

	// upload file operation
	// verify bucket name
	if !VerifyBucketName(bucketName) {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, ERR_InvalidBucketName))
		c.JSON(http.StatusBadRequest, ERR_InvalidBucketName)
		return
	}

	// Determine whether to authorize the space
	httpCode, err = n.VerifyGrantor(pkey)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(httpCode, err)
		return
	}

	userBrief.User = types.NewAccountID(pkey)
	userBrief.File_name = types.Bytes(putName)
	userBrief.Bucket_name = types.Bytes(bucketName)

	// Is Stored
	httpCode, err = n.IsStored(c.Request.Header.Get(Header_Digest), userBrief)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(httpCode, err)
		return
	}

	// Judging the length of the body
	content_length := c.Request.ContentLength
	if content_length <= 0 {
		n.Logs.Upfile("error", fmt.Sprintf("[%v] %v", clientIp, ERR_EmptyFile))
		c.JSON(http.StatusBadRequest, ERR_EmptyFile)
		return
	}

	filesize, filehash, fpath, httpCode, err = n.SaveFormFile(c, account, putName)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(httpCode, err)
		return
	}

	// Chunk the file
	chunkPath, lastSize, err := Chunking(fpath)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	// Calculate merkle hash tree
	hTree, err := hashtree.NewHashTree(chunkPath)
	if err != nil {
		n.Logs.Upfile("error", fmt.Sprintf("[%v] %v", clientIp))
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	// Merkel root hash
	roothash = hex.EncodeToString(hTree.MerkleRoot())
	n.Logs.Upfile("info", fmt.Sprintf("[%v] Merkel root hash: %v", clientIp, roothash))

	//Judge whether the file has been uploaded
	httpCode, err = n.IsUploaded(roothash)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(httpCode, err)
		return
	}

	// Record file hash and corresponding Merkel hash
	n.Cach.Put([]byte(Key_Digest+filehash), []byte(roothash))

	// Record file Merkle hash and all corresponding leaf hashes
	var slicesHash string
	for i := 0; i < len(chunkPath); i++ {
		slicesHash += filepath.Base(chunkPath[i])
		if (i + 1) < len(chunkPath) {
			slicesHash += "#"
		}
	}
	n.Cach.Put([]byte(Key_Slices+roothash), []byte(slicesHash))

	// Is Stored
	httpCode, err = n.IsStored(roothash, userBrief)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(httpCode, err)
		return
	}

	// Upload Deal
	txHash, err = n.Chn.UploadDeal(roothash, uint64(filesize), chunkPath, userBrief)
	if err != nil || txHash == "" {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	// File Storage Progress
	fileStorageProgress.FileId = roothash
	fileStorageProgress.FileSize = filesize
	fileStorageProgress.FileState = chain.FILE_STATE_PENDING
	fileStorageProgress.IsUpload = true
	fileStorageProgress.IsCheck = true
	fileStorageProgress.IsShard = true

	val, _ := json.Marshal(&fileStorageProgress)
	n.Cach.Put([]byte(Key_StoreProgress+roothash), val)

	// Record in tracklist
	os.Create(filepath.Join(n.TrackDir, roothash))

	// Start the file backup thread
	go n.task_StoreFile(chunkPath, roothash, lastSize)

	n.Logs.Upfile("info", fmt.Sprintf("[%v] Upload success: %v", clientIp, roothash))
	c.JSON(http.StatusOK, roothash)
	return
}

func (n *Node) task_StoreFile(fpath []string, fid string, lastsize int64) {
	defer func() {
		if err := recover(); err != nil {
			n.Logs.Pnc("error", utils.RecoverError(err))
		}
	}()
	var ch_Scheduler = make(chan string, 1)

	n.Logs.Upfile("info", fmt.Sprint("[%v] Start the file backup management process", fid))
	go n.uploadToStorage(ch_Scheduler, fpath, fid, lastsize)
	for {
		select {
		case result := <-ch_Scheduler:
			if result == ERR_RETRY {
				go n.uploadToStorage(ch_Scheduler, fpath, fid, lastsize)
				time.Sleep(configs.BlockInterval)
			} else if _, err := utils.DecodePublicKeyOfCessAccount(result); err == nil {
				var fileSt client.StorageProgress
				val_old, _ := n.Cach.Get([]byte(fid))
				json.Unmarshal(val_old, &fileSt)
				fileSt.IsScheduler = true
				fileSt.Scheduler = result
				val_new, _ := json.Marshal(&fileSt)
				n.Cach.Put([]byte(fid), val_new)
				n.Logs.Upfile("info", fmt.Sprintf("[%v] File scheduling succeeded", fid))
				return
			} else {
				go n.uploadToStorage(ch_Scheduler, fpath, fid, lastsize)
				time.Sleep(configs.BlockInterval)
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

	for i := 0; i < len(fpath); i++ {
		n.Logs.Upfile("info", fmt.Sprintf("[%v] slice-%d: %v", fid, i, filepath.Base(fpath[i])))
	}

	//Judge whether the file has been uploaded
	filedealinfo, err := n.Chn.GetFileDealMap(fid)
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] err: %v", fid, err))
		ch <- ERR_RETRY
		return
	}

	accAssign, _ := utils.EncodePublicKeyAsCessAccount(filedealinfo.Scheduler[:])
	scheList, err := n.Chn.GetSchedulerList()
	if err != nil {
		n.Logs.Upfile("err", fmt.Sprintf("[%v] err: %v", fid, err))
		ch <- ERR_RETRY
		return
	}

	n.Logs.Upfile("info", fmt.Sprintf("[%v] Assigned: %v", fid, accAssign))

	for i := 0; i < len(scheList); i++ {
		accTemp, _ := utils.EncodePublicKeyAsCessAccount(scheList[i].ControllerUser[:])
		n.Logs.Upfile("info", fmt.Sprintf("[%v] Found: %v", fid, accTemp))
		if accTemp != accAssign {
			continue
		}
		wsURL := fmt.Sprintf("%d.%d.%d.%d:%d",
			scheList[i].Ip.Value[0],
			scheList[i].Ip.Value[1],
			scheList[i].Ip.Value[2],
			scheList[i].Ip.Value[3],
			scheList[i].Ip.Port,
		)

		n.Logs.Upfile("info", fmt.Sprintf("Will be send to: %v", accAssign))

		conTcp, err := dialTcpServer(wsURL)
		if err != nil {
			n.Logs.Upfile("err", fmt.Sprintf("[%v] err: %v", fid, err))
			break
		}

		token, err := client.AuthReq(conTcp, n.Cfile.GetCtrlPrk())
		if err != nil {
			conTcp.Close()
			n.Logs.Upfile("err", fmt.Sprintf("[%v] err: %v", fid, err))
			break
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
				n.Logs.Upfile("err", fmt.Sprintf("[%v] err: %v", fid, err))
				conTcp.Close()
				break
			}
		}
		if err != nil {
			break
		}
		ch <- accAssign
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
			fmt.Println("Track files: ", files)
			for _, v := range files {
				sches, err := n.Chn.GetSchedulerList()
				if err != nil {
					continue
				}

				val, _ := n.Cach.Get([]byte(filepath.Base(v)))
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
							os.Remove(filepath.Join(n.FileDir, v+".tag"))
						}
					}
				}
			}
		}
	}
}

func Chunking(fpath string) ([]string, int64, error) {
	fstat, err := os.Stat(fpath)
	if err != nil {
		return nil, 0, err
	}
	if fstat.IsDir() {
		return nil, 0, fmt.Errorf("Not a file")
	}

	count := fstat.Size() / configs.SIZE_SLICE

	lastSize := fstat.Size() % configs.SIZE_SLICE
	if lastSize > 0 {
		count += 1
	}

	rtnList := make([]string, count)

	appendSize := configs.SIZE_SLICE - lastSize

	fbase, err := os.Open(fpath)
	if err != nil {
		return nil, 0, err
	}
	buf := make([]byte, configs.SIZE_SLICE)
	appendSizeBuf := make([]byte, appendSize)
	baseDir := filepath.Dir(fpath)
	for i := int64(0); i < count; i++ {
		fbase.Seek(i*configs.SIZE_SLICE, 0)
		n, err := fbase.Read(buf)
		if err != nil && err != io.EOF {
			return nil, 0, err
		}

		tempPath := fpath + fmt.Sprintf("%d", i)
		fs, err := os.Create(tempPath)
		if err != nil {
			return nil, 0, err
		}

		if (i + 1) < count {
			if n != configs.SIZE_SLICE {
				fs.Close()
				return nil, 0, err
			}
			_, err = fs.Write(buf[:n])
			if err != nil {
				fs.Close()
				return nil, 0, err
			}
		} else {
			if int64(n) != lastSize {
				fs.Close()
				return nil, 0, err
			}
			_, err = fs.Write(buf[:n])
			if err != nil {
				fs.Close()
				return nil, 0, err
			}
			_, err = fs.Write(appendSizeBuf)
			if err != nil {
				fs.Close()
				return nil, 0, err
			}
		}
		err = fs.Sync()
		if err != nil {
			fs.Close()
			return nil, 0, err
		}
		fs.Close()

		rtnList[i], err = utils.CalcPathSHA256(tempPath)
		if err != nil {
			return nil, 0, err
		}
		os.Rename(tempPath, fmt.Sprintf("%v/%v", baseDir, rtnList[i]))
		rtnList[i] = fmt.Sprintf("%v/%v", baseDir, rtnList[i])
	}

	return rtnList, lastSize, nil
}
