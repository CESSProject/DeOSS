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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/chain"
	"github.com/CESSProject/DeOSS/pkg/erasure"
	"github.com/CESSProject/DeOSS/pkg/utils"
	cesskeyring "github.com/CESSProject/go-keyring"
	"github.com/gin-gonic/gin"
)

type RtnFileType struct {
	FileSize   uint64
	FileState  string
	UserBriefs []RtnUserBrief
	BlockInfo  []RtnBlockInfo
}

type RtnUserBrief struct {
	User       string
	FileName   string
	BucketName string
}

// file block info
type RtnBlockInfo struct {
	MinerId  uint64
	BlockId  string
	MinerIp  string
	MinerAcc string
}

// It is used to authorize users
func (n *Node) GetHandle(c *gin.Context) {
	getName := c.Param("name")
	if getName == "version" {
		c.JSON(200, configs.Version)
		return
	}
	if strings.ContainsAny(getName, ".") {
		fext := filepath.Ext(getName)
		contenttype, ok := contentType.Load(strings.ToLower(fext))
		if !ok {
			contenttype = "application/octet-stream"
		}
		hash := strings.TrimSuffix(getName, fext)
		if len(hash) == int(unsafe.Sizeof(chain.FileHash{})) {
			fpath := filepath.Join(n.FileDir, hash)
			fstat, err := os.Stat(fpath)
			if err == nil {

				// c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%v", getName))
				// c.Writer.Header().Add("Content-Type", "application/octet-stream")
				// c.File(fpath)

				c.Header("Accept-ranges", "bytes")
				c.Writer.Header().Add("Access-control-allow-headers", "Content-Type")
				c.Writer.Header().Add("Access-control-allow-headers", "Range")
				c.Writer.Header().Add("Access-control-allow-headers", "User-Agent")
				c.Writer.Header().Add("Access-control-allow-headers", "X-Request-With")
				c.Header("Accept-control-allow-methods", "GET")
				c.Header("Accept-control-allow-origin", "*")
				c.Writer.Header().Add("Accept-control-expose-headers", "Content-Range")
				c.Writer.Header().Add("Accept-control-expose-headers", "X-Chunked-Output")
				c.Writer.Header().Add("Accept-control-expose-headers", "X-Stream-Output")
				c.Header("Cache-control", "public, max-age=29030400, immutable")
				c.Header("Content-length", fmt.Sprintf("%d", fstat.Size()))
				c.Header("Content-type", contenttype.(string))
				c.Header("Cache-Control", "max-age=600")
				if contenttype.(string) == "application/octet-stream" {
					c.Header("Content-disposition", fmt.Sprintf("attachment; filename=%v", getName))
				} else {
					c.Header("Content-disposition", fmt.Sprintf("inline; filename=%v", getName))
				}
				f, _ := os.Open(fpath)
				io.Copy(c.Writer, f)
				select {
				case <-c.Request.Context().Done():
					return
				}
			}

			// file meta info
			fmeta, err := n.Chain.GetFileMetaInfo(hash)
			if err != nil {
				if err.Error() == chain.ERR_Empty {
					c.JSON(404, "NotFound")
					return
				}
				c.JSON(500, "InternalError")
				return
			}

			if string(fmeta.State) != chain.FILE_STATE_ACTIVE {
				c.JSON(403, "BackingUp")
				return
			}

			r := len(fmeta.BlockInfo) / 3
			d := len(fmeta.BlockInfo) - r
			down_count := 0
			for i := 0; i < len(fmeta.BlockInfo); i++ {
				// Download the file from the scheduler service
				fname := filepath.Join(n.FileDir, string(fmeta.BlockInfo[i].BlockId[:]))
				if len(fmeta.BlockInfo) == 1 {
					fname = fname[:(len(fname) - 4)]
				}
				mip := fmt.Sprintf("%d.%d.%d.%d:%d",
					fmeta.BlockInfo[i].MinerIp.Value[0],
					fmeta.BlockInfo[i].MinerIp.Value[1],
					fmeta.BlockInfo[i].MinerIp.Value[2],
					fmeta.BlockInfo[i].MinerIp.Value[3],
					fmeta.BlockInfo[i].MinerIp.Port,
				)
				err = n.downloadFromStorage(fname, int64(fmeta.BlockInfo[i].BlockSize), mip)
				if err != nil {
					n.Logs.Downfile("error", fmt.Errorf("[%v] Downloading %drd shard err: %v", c.ClientIP(), i, err))
				} else {
					down_count++
				}
				if down_count >= d {
					break
				}
			}

			err = erasure.ReedSolomon_Restore(n.FileDir, getName, d, r, uint64(fmeta.Size))
			if err != nil {
				n.Logs.Downfile("error", fmt.Errorf("[%v] ReedSolomon_Restore: %v", c.ClientIP(), err))
				c.JSON(500, "InternalError")
				return
			}

			if r > 0 {
				fstat, err := os.Stat(fpath)
				if err != nil {
					c.JSON(500, "InternalError")
					return
				}
				if uint64(fstat.Size()) > uint64(fmeta.Size) {
					tempfile := fpath + ".temp"
					copyFile(fpath, tempfile, int64(fmeta.Size))
					os.Remove(fpath)
					os.Rename(tempfile, fpath)
				}
			}
			c.Header("Accept-ranges", "bytes")
			c.Writer.Header().Add("Access-control-allow-headers", "Content-Type")
			c.Writer.Header().Add("Access-control-allow-headers", "Range")
			c.Writer.Header().Add("Access-control-allow-headers", "User-Agent")
			c.Writer.Header().Add("Access-control-allow-headers", "X-Request-With")
			c.Header("Accept-control-allow-methods", "GET")
			c.Header("Accept-control-allow-origin", "*")
			c.Writer.Header().Add("Accept-control-expose-headers", "Content-Range")
			c.Writer.Header().Add("Accept-control-expose-headers", "X-Chunked-Output")
			c.Writer.Header().Add("Accept-control-expose-headers", "X-Stream-Output")
			c.Header("Cache-control", "public, max-age=29030400, immutable")
			c.Header("Content-length", fmt.Sprintf("%d", fstat.Size()))
			c.Header("Content-type", fmt.Sprintf("%s", contenttype.(string)))
			if contenttype.(string) == "application/octet-stream" {
				c.Header("Content-disposition", fmt.Sprintf("attachment; filename=%v", getName))
			} else {
				c.Header("Content-disposition", fmt.Sprintf("inline; filename=%v", getName))
			}
			f, _ := os.Open(fpath)
			io.Copy(c.Writer, f)
			select {
			case <-c.Request.Context().Done():
				return
			}
		}
	}

	// operation
	operation := c.Request.Header.Get(configs.Header_Operation)
	// view file
	if len(getName) == int(unsafe.Sizeof(chain.FileHash{})) && operation != "" {
		if operation == "view" {
			fmeta, err := n.Chain.GetFileMetaInfo(getName)
			if err != nil {
				if err.Error() == chain.ERR_Empty {
					c.JSON(404, "NotFound")
					return
				}
				c.JSON(500, "InternalError")
				return
			}

			var fileSt FileStoreInfo

			if string(fmeta.State) == chain.FILE_STATE_ACTIVE {
				fileSt.FileId = getName
				fileSt.FileSize = int64(fmeta.Size)
				fileSt.FileState = chain.FILE_STATE_ACTIVE
				fileSt.IsUpload = true
				fileSt.IsCheck = true
				fileSt.IsScheduler = true
				fileSt.IsShard = true
				fileSt.Miners = make(map[int]string, len(fmeta.BlockInfo))
				for i := 0; i < len(fmeta.BlockInfo); i++ {
					fileSt.Miners[i], _ = utils.EncodePublicKeyAsCessAccount(fmeta.BlockInfo[i].MinerAcc[:])
				}
				c.JSON(http.StatusOK, fileSt)
				return
			}

			val, err := n.Cache.Get([]byte(getName))
			if err != nil {
				fileSt.FileId = getName
				fileSt.FileSize = int64(fmeta.Size)
				fileSt.FileState = chain.FILE_STATE_ACTIVE
				fileSt.IsUpload = true
				fileSt.IsCheck = true
				fileSt.IsShard = true
				fileSt.IsScheduler = false
				c.JSON(http.StatusOK, fileSt)
				return
			}

			json.Unmarshal(val, &fileSt)
			c.JSON(http.StatusOK, fileSt)
			return
		}
		if operation == "download" {
			// local cache
			fpath := filepath.Join(n.FileDir, getName)
			_, err := os.Stat(fpath)
			if err == nil {
				c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%v", getName))
				c.Writer.Header().Add("Content-Type", "application/octet-stream")
				c.File(fpath)
				return
			}

			// file meta info
			fmeta, err := n.Chain.GetFileMetaInfo(getName)
			if err != nil {
				if err.Error() == chain.ERR_Empty {
					c.JSON(404, "NotFound")
					return
				}
				c.JSON(500, "InternalError")
				return
			}

			if string(fmeta.State) != chain.FILE_STATE_ACTIVE {
				c.JSON(403, "BackingUp")
				return
			}

			r := len(fmeta.BlockInfo) / 3
			d := len(fmeta.BlockInfo) - r
			down_count := 0
			for i := 0; i < len(fmeta.BlockInfo); i++ {
				// Download the file from the scheduler service
				fname := filepath.Join(n.FileDir, string(fmeta.BlockInfo[i].BlockId[:]))
				if len(fmeta.BlockInfo) == 1 {
					fname = fname[:(len(fname) - 4)]
				}
				mip := fmt.Sprintf("%d.%d.%d.%d:%d",
					fmeta.BlockInfo[i].MinerIp.Value[0],
					fmeta.BlockInfo[i].MinerIp.Value[1],
					fmeta.BlockInfo[i].MinerIp.Value[2],
					fmeta.BlockInfo[i].MinerIp.Value[3],
					fmeta.BlockInfo[i].MinerIp.Port,
				)
				err = n.downloadFromStorage(fname, int64(fmeta.BlockInfo[i].BlockSize), mip)
				if err != nil {
					n.Logs.Downfile("error", fmt.Errorf("[%v] Downloading %drd shard err: %v", c.ClientIP(), i, err))
				} else {
					down_count++
				}
				if down_count >= d {
					break
				}
			}

			err = erasure.ReedSolomon_Restore(n.FileDir, getName, d, r, uint64(fmeta.Size))
			if err != nil {
				n.Logs.Downfile("error", fmt.Errorf("[%v] ReedSolomon_Restore: %v", c.ClientIP(), err))
				c.JSON(500, "InternalError")
				return
			}

			if r > 0 {
				fstat, err := os.Stat(fpath)
				if err != nil {
					c.JSON(500, "InternalError")
					return
				}
				if uint64(fstat.Size()) > uint64(fmeta.Size) {
					tempfile := fpath + ".temp"
					copyFile(fpath, tempfile, int64(fmeta.Size))
					os.Remove(fpath)
					os.Rename(tempfile, fpath)
				}
			}

			c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%v", getName))
			c.Writer.Header().Add("Content-Type", "application/octet-stream")
			c.File(fpath)
			return
		}
		c.JSON(400, "InvalidHead.Operation")
		return
	}

	// account
	account := c.Request.Header.Get(configs.Header_Account)
	if account == "" {
		c.JSON(400, "InvalidHead.MissingAccount")
		return
	}

	pkey, err := utils.DecodePublicKeyOfCessAccount(account)
	if err != nil {
		c.JSON(400, "InvalidHead.Account")
		return
	}

	// view bucket
	if VerifyBucketName(getName) {
		bucketInfo, err := n.Chain.GetBucketInfo(pkey, getName)
		if err != nil {
			if err.Error() == chain.ERR_Empty {
				c.JSON(404, "NotFound")
				return
			}
			c.JSON(500, "InternalError")
			return
		}
		filesHash := make([]string, len(bucketInfo.Objects_list))
		for i := 0; i < len(bucketInfo.Objects_list); i++ {
			filesHash[i] = string(bucketInfo.Objects_list[i][:])
		}
		data := struct {
			Num   uint32
			Files []string
		}{
			Num:   uint32(bucketInfo.Objects_num),
			Files: filesHash,
		}
		c.JSON(http.StatusOK, data)
		return
	}

	// view bucket list
	if getName == "*" {
		bucketList, err := n.Chain.GetBucketList(pkey)
		if err != nil {
			if err.Error() == chain.ERR_Empty {
				c.JSON(404, "NotFound")
				return
			}
			c.JSON(500, "InternalError")
			return
		}
		bucket := make([]string, len(bucketList))
		for i := 0; i < len(bucketList); i++ {
			bucket[i] = string(bucketList[i][:])
		}
		c.JSON(http.StatusOK, bucket)
		return
	}

	c.JSON(400, "InvalidParameter.Name")
}

// Download files from cess storage service
func (n *Node) downloadFromStorage(fpath string, fsize int64, mip string) error {
	fsta, err := os.Stat(fpath)
	if err == nil {
		if fsta.Size() == fsize {
			return nil
		} else {
			os.Remove(fpath)
		}
	}

	msg := utils.GetRandomcode(16)

	kr, _ := cesskeyring.FromURI(n.Confile.GetCtrlPrk(), cesskeyring.NetSubstrate{})
	// sign message
	sign, err := kr.Sign(kr.SigningContext([]byte(msg)))
	if err != nil {
		return err
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", mip)
	if err != nil {
		return err
	}

	conTcp, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return err
	}
	return NewClient(NewTcp(conTcp), n.FileDir, nil).RecvFile(filepath.Base(fpath), fsize, n.Chain.GetPublicKey(), []byte(msg), sign[:])
}

func copyFile(src, dst string, length int64) error {
	srcfile, err := os.OpenFile(src, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer srcfile.Close()
	dstfile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer dstfile.Close()

	var buf = make([]byte, 64*1024)
	var count int64
	for {
		n, err := srcfile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		count += int64(n)
		if count < length {
			dstfile.Write(buf[:n])
		} else {
			tail := count - length
			if n >= int(tail) {
				dstfile.Write(buf[:(n - int(tail))])
			}
		}
	}

	return nil
}
