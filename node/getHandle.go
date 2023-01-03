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
	"net/http"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/CESSProject/cess-oss/pkg/client"
	"github.com/CESSProject/cess-oss/pkg/utils"
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
	// operation
	operation := c.Request.Header.Get(configs.Header_Operation)
	// view file
	if len(getName) == int(unsafe.Sizeof(chain.FileHash{})) && operation != "" {
		if operation == Opt_View {
			fmeta, err := n.Chn.GetFileMetaInfo(getName)
			if err != nil {
				if err.Error() == chain.ERR_Empty {
					c.JSON(404, "NotFound")
					return
				}
				c.JSON(500, "InternalError")
				return
			}

			var fileSt client.StorageProgress
			fileSt.Backups = make([]map[int]string, len(fmeta.Backups))
			for i := 0; i < len(fmeta.Backups); i++ {
				fileSt.Backups[i] = make(map[int]string)
			}
			if string(fmeta.State) == chain.FILE_STATE_ACTIVE {
				fileSt.FileId = getName
				fileSt.FileSize = int64(fmeta.Size)
				fileSt.FileState = chain.FILE_STATE_ACTIVE
				fileSt.IsUpload = true
				fileSt.IsCheck = true
				fileSt.IsScheduler = true
				fileSt.IsShard = true
				for i := 0; i < len(fmeta.Backups); i++ {
					for j := 0; j < len(fmeta.Backups[i].Slice_info); j++ {
						fileSt.Backups[i][j], _ = utils.EncodePublicKeyAsCessAccount(fmeta.Backups[i].Slice_info[j].Miner_acc[:])
					}
				}
				c.JSON(http.StatusOK, fileSt)
				return
			}

			val, err := n.Cach.Get([]byte(getName))
			if err != nil {
				fileSt.FileId = getName
				fileSt.FileSize = int64(fmeta.Size)
				fileSt.FileState = chain.FILE_STATE_ACTIVE
				fileSt.IsUpload = true
				fileSt.IsCheck = true
				fileSt.IsShard = true
				fileSt.IsScheduler = false
				fileSt.Backups = nil
				c.JSON(http.StatusOK, fileSt)
				return
			}

			json.Unmarshal(val, &fileSt)
			c.JSON(http.StatusOK, fileSt)
			return
		}
		if operation == Opt_Download {
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
			fmeta, err := n.Chn.GetFileMetaInfo(getName)
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

			var fsize int64

			for j := 0; j < len(fmeta.Backups[0].Slice_info); j++ {
				for i := 0; i < len(fmeta.Backups); i++ {
					// Download the file from the scheduler service
					fname := filepath.Join(n.FileDir, string(fmeta.Backups[i].Slice_info[j].Slice_hash[:]))
					mip := fmt.Sprintf("%d.%d.%d.%d:%d",
						fmeta.Backups[i].Slice_info[j].Miner_ip.Value[0],
						fmeta.Backups[i].Slice_info[j].Miner_ip.Value[1],
						fmeta.Backups[i].Slice_info[j].Miner_ip.Value[2],
						fmeta.Backups[i].Slice_info[j].Miner_ip.Value[3],
						fmeta.Backups[i].Slice_info[j].Miner_ip.Port,
					)
					if (j + 1) == len(fmeta.Backups[i].Slice_info) {
						fsize = int64(fmeta.Size % configs.SIZE_SLICE)
					} else {
						fsize = configs.SIZE_SLICE
					}
					err = n.downloadFromStorage(fname, fsize, mip)
					if err != nil {
						n.Logs.Downfile("error", fmt.Errorf("[%v] Downloading %drd shard err: %v", c.ClientIP(), i, err))
						if (i + 1) == len(fmeta.Backups) {
							c.JSON(500, "InternalError")
							return
						}
						continue
					}
				}
			}

			f, err := os.Create(fpath)
			if err != nil {
				c.JSON(500, "InternalError")
				return
			}
			var buf = make([]byte, 64*1024)
			var num int
			for j := 0; j < len(fmeta.Backups[0].Slice_info); j++ {
				fslice, err := os.Open(filepath.Join(n.FileDir, string(fmeta.Backups[0].Slice_info[j].Slice_hash[:])))
				if err != nil {
					f.Close()
					c.JSON(500, "InternalError")
					return
				}
				for {
					num, err = fslice.Read(buf)
					if err != nil && err != io.EOF {
						c.JSON(500, "InternalError")
						return
					}
					if num == 0 {
						break
					}
					f.Write(buf[:num])
					f.Sync()
				}
			}
			f.Close()

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
		bucketInfo, err := n.Chn.GetBucketInfo(pkey, getName)
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
		bucketList, err := n.Chn.GetBucketList(pkey)
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
		} else if fsta.Size() > fsize {
			os.Remove(fpath)
		}
	}

	conTcp, err := dialTcpServer(mip)
	if err != nil {
		n.Logs.Upfile("err", fmt.Errorf("dial %v err: %v", mip, err))
		return err
	}

	token, err := client.AuthReq(conTcp, n.Cfile.GetCtrlPrk())
	if err != nil {
		n.Logs.Upfile("err", fmt.Errorf("dial %v err: %v", mip, err))
		return err
	}

	err = client.DownReq(conTcp, token, fpath, fsize)

	return err
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
