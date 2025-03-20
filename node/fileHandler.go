/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/lru"
	"github.com/CESSProject/DeOSS/common/tracker"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/common/workspace"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type FileHandler struct {
	chain.Chainer
	workspace.Workspace
	tracker.Tracker
	logger.Logger
	*confile.Config
	*rate.Limiter
	*lru.LRUCache
}

// file meta info
type Metadata struct {
	Fid   string         `json:"fid"`
	Size  uint64         `json:"size"`
	Owner []RtnUserBrief `json:"owner"`
}

type RtnUserBrief struct {
	User     string `json:"user"`
	FileName string `json:"file_name"`
}

// location info
type NodeInfo struct {
	Account  string   `json:"account"`
	Location Location `json:"location"`
}

type Location struct {
	Longitude float64 `json:"longitude"`
	Latitude  float64 `json:"latitude"`
}

type fileTypeRecord struct {
	lock   *sync.Mutex
	record map[string]string
}

type UserFilesInfo struct {
	Territory string `json:"territory"`
	Fid       string `json:"fid"`
	Size      uint64 `json:"size"`
}

var frecord *fileTypeRecord

func init() {
	frecord = &fileTypeRecord{
		lock:   new(sync.Mutex),
		record: make(map[string]string, 100),
	}
}

func (f *fileTypeRecord) AddToFileRecord(fid, format string) {
	f.lock.Lock()
	f.record[fid] = format
	f.lock.Unlock()
}

func (f *fileTypeRecord) GetFileFormat(fid string) (string, bool) {
	f.lock.Lock()
	value, ok := f.record[fid]
	f.lock.Unlock()
	return value, ok
}

func NewFileHandler(cli chain.Chainer, track tracker.Tracker, ws workspace.Workspace, lg logger.Logger, cfg *confile.Config, lru *lru.LRUCache) *FileHandler {
	return &FileHandler{Chainer: cli, Tracker: track, Workspace: ws, Logger: lg, Config: cfg, Limiter: rate.NewLimiter(rate.Every(time.Millisecond*10), 20), LRUCache: lru}
}

func (f *FileHandler) RegisterRoutes(server *gin.Engine) {
	filegroup := server.Group("/file")
	filegroup.Use(
		func(ctx *gin.Context) {
			if !f.Limiter.Allow() {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_ServerBusy,
				})
				return
			}
			ctx.Next()
		},
	)
	filegroup.PUT("",
		func(ctx *gin.Context) {
			acc, pk, ok := VerifySignatureMdl(ctx)
			if !ok {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			ctx.Set("account", acc)
			ctx.Set("publickey", hex.EncodeToString(pk))
			ctx.Next()
		},
		func(ctx *gin.Context) {
			acc, ok := ctx.Get("account")
			if !ok {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			if !CheckPermissionsMdl(fmt.Sprintf("%v", acc), f.Config.Access.Mode, f.Config.User.Account, f.Config.Access.Account) {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			ctx.Next()
		},
		f.UploadFormFileHandle,
	)

	filegroup.DELETE(fmt.Sprintf("/:%s", HTTP_ParameterName_Fid),
		func(ctx *gin.Context) {
			acc, pk, ok := VerifySignatureMdl(ctx)
			if !ok {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			ctx.Set("account", acc)
			ctx.Set("publickey", hex.EncodeToString(pk))
			ctx.Next()
		},
		func(ctx *gin.Context) {
			acc, ok := ctx.Get("account")
			if !ok {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			if !CheckPermissionsMdl(fmt.Sprintf("%v", acc), f.Config.Access.Mode, f.Config.User.Account, f.Config.Access.Account) {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			ctx.Next()
		},
		f.DeleteFileHandle,
	)

	filegroup.GET(fmt.Sprintf("/download/:%s", HTTP_ParameterName_Fid), f.DownloadFileHandle)
	filegroup.GET(fmt.Sprintf("/open/:%s", HTTP_ParameterName_Fid), f.OpenFileHandle)
	filegroup.GET(fmt.Sprintf("/metadata/:%s", HTTP_ParameterName_Fid), f.GetMetadataHandle)
	filegroup.GET(fmt.Sprintf("/location/:%s", HTTP_ParameterName_Fid), f.GetLocationhandle)
	filegroup.GET("/list", f.GetUserFilesHandle)

	fragmentgroup := server.Group("/fragment")
	fragmentgroup.GET("/download",
		func(ctx *gin.Context) {
			acc, pk, ok := VerifySignatureMdl(ctx)
			if !ok {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			ctx.Set("account", acc)
			ctx.Set("publickey", hex.EncodeToString(pk))
			ctx.Next()
		},
		func(ctx *gin.Context) {
			acc, ok := ctx.Get("account")
			if !ok {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			if !CheckPermissionsMdl(fmt.Sprintf("%v", acc), f.Config.Access.Mode, f.Config.User.Account, f.Config.Access.Account) {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			ctx.Next()
		},
		f.DownloadFragmentHandle,
	)
}

func (f *FileHandler) GetLocationhandle(c *gin.Context) {
	fid := c.Param(HTTP_ParameterName_Fid)

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	f.Logopen("info", clientIp+" get location: "+fid)

	metadata, err := f.QueryFile(fid, -1)
	if err != nil {
		ReturnJSON(c, 404, ERR_NotFound, nil)
		return
	}

	length := chain.ParShards + chain.DataShards
	var data = make(map[string]NodeInfo, len(metadata.SegmentList))
	account := ""
	key := ""

	for j := 0; j < length; j++ {
		key = fmt.Sprintf("%d batch fragments", j)
		account, _ = sutils.EncodePublicKeyAsCessAccount(metadata.SegmentList[0].FragmentList[0].Miner[:])
		longitude, latitude, err := CheckMinerLocation(f.Chainer, metadata.SegmentList[0].FragmentList[0].Miner[:])
		if err != nil {
			data[key] = NodeInfo{
				Account: account,
				Location: Location{
					Longitude: 0,
					Latitude:  0,
				},
			}
			continue
		}
		data[key] = NodeInfo{
			Account: account,
			Location: Location{
				Longitude: longitude,
				Latitude:  latitude,
			},
		}
	}
	ReturnJSON(c, 200, MSG_OK, data)
}

func (f *FileHandler) GetMetadataHandle(c *gin.Context) {
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	fid := c.Param(HTTP_ParameterName_Fid)
	f.Logget("info", clientIp+" get metadata of the file: "+fid)

	var fileMetadata Metadata
	fileMetadata.Fid = fid
	fmeta, err := f.QueryFile(fid, -1)
	if err != nil {
		if !errors.Is(err, chain.ERR_RPC_EMPTY_VALUE) {
			f.Logget("err", clientIp+" QueryFile failed: "+err.Error())
			ReturnJSON(c, 403, ERR_RPCConnection, nil)
			return
		}

		sorder, err := f.QueryDealMap(fid, -1)
		if err != nil {
			if !errors.Is(err, chain.ERR_RPC_EMPTY_VALUE) {
				f.Logget("err", clientIp+" QueryDealMap failed: "+err.Error())
				ReturnJSON(c, 403, ERR_RPCConnection, nil)
				return
			}

			traceFile, err := f.ParsingTraceFile(fid)
			if err != nil {
				f.Logget("err", clientIp+" ParsingTraceFile failed: "+err.Error())
				ReturnJSON(c, 403, "The file has not been uploaded to the chain yet, please go to the gateway where the file was uploaded to query.", nil)
				return
			}

			fileMetadata.Size = traceFile.FileSize
			fileMetadata.Owner = make([]RtnUserBrief, 1)
			fileMetadata.Owner[0].FileName = traceFile.FileName
			fileMetadata.Owner[0].User, _ = sutils.EncodePublicKeyAsCessAccount(traceFile.Owner)
			f.Logget("info", clientIp+" get metadata from file suc of the file: "+fid)
			ReturnJSON(c, 200, MSG_OK, fileMetadata)
		}

		fileMetadata.Size = sorder.FileSize.Uint64()
		fileMetadata.Owner = make([]RtnUserBrief, 1)
		fileMetadata.Owner[0].FileName = string(sorder.User.FileName)
		fileMetadata.Owner[0].User, _ = sutils.EncodePublicKeyAsCessAccount(sorder.User.User[:])
		f.Logget("info", clientIp+" get metadata from file suc of the file: "+fid)
		ReturnJSON(c, 200, MSG_OK, fileMetadata)
		return
	}

	fileMetadata.Size = fmeta.FileSize.Uint64()
	fileMetadata.Owner = make([]RtnUserBrief, len(fmeta.Owner))
	for i := 0; i < len(fmeta.Owner); i++ {
		fileMetadata.Owner[i].FileName = string(fmeta.Owner[i].FileName)
		fileMetadata.Owner[i].User, _ = sutils.EncodePublicKeyAsCessAccount(fmeta.Owner[i].User[:])
	}
	f.Logget("info", clientIp+" get metadata from file suc of the file: "+fid)
	ReturnJSON(c, 200, MSG_OK, fileMetadata)
}

func (f *FileHandler) GetUserFilesHandle(c *gin.Context) {
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	account, ok := c.GetQuery(HTTPHeader_Account)
	if !ok {
		account = c.Request.Header.Get(HTTPHeader_Account)
		if account == "" {
			f.Logget("err", clientIp+"GetUserFilesHandle: not found account")
			ReturnJSON(c, 400, "Please set your Account in the header or url", nil)
			return
		}
	}

	puk, err := sutils.ParsingPublickey(account)
	if err != nil {
		f.Logget("err", clientIp+"GetUserFilesHandle-ParsingPublickey: "+err.Error())
		ReturnJSON(c, 400, "Invalid CESS account: "+account, nil)
		return
	}

	territory, ok := c.GetQuery(HTTPHeader_Territory)
	if !ok {
		territory = c.Request.Header.Get(HTTPHeader_Territory)
	}

	f.Logget("info", clientIp+" get file list request: "+account+" "+territory)

	userFileSlice, err := f.QueryUserHoldFileList(puk, -1)
	if err != nil {
		if !errors.Is(err, chain.ERR_RPC_EMPTY_VALUE) {
			f.Logget("err", clientIp+"GetUserFilesHandle-QueryUserHoldFileList: "+err.Error())
			ReturnJSON(c, 403, ERR_RPCConnection, nil)
			return
		}
	}

	if territory == "" {
		ReturnJSON(c, 200, "ok", userFileSlice)
		return
	}

	var territoryFiles []UserFilesInfo
	for i := 0; i < len(userFileSlice); i++ {
		if string(userFileSlice[i].TerritoryName) == territory {
			territoryFiles = append(territoryFiles, UserFilesInfo{
				Territory: territory,
				Fid:       string(userFileSlice[i].Filehash[:]),
				Size:      userFileSlice[i].FileSize.Uint64(),
			})
		}
	}
	ReturnJSON(c, 200, "ok", territoryFiles)
	return
}

func (f *FileHandler) OpenFileHandle(c *gin.Context) {
	fid := c.Param(HTTP_ParameterName_Fid)
	format := c.Request.Header.Get(HTTPHeader_Format)
	rgn := c.Request.Header.Get(HTTPHeader_Range)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	if strings.Contains(fid, ".") {
		temp := strings.Split(fid, ".")
		fid = temp[0]
		if format == "" && len(temp) > 1 {
			format = temp[1]
		}
	} else {
		if len(fid) > chain.FileHashLen {
			tmp_fid := fid[:chain.FileHashLen]
			format = fid[chain.FileHashLen:]
			fid = tmp_fid
		} else if len(fid) < chain.FileHashLen {
			f.Logopen("err", clientIp+" invalid fid: "+fid)
			c.JSON(404, "invalid fid")
			ReturnJSON(c, 400, ERR_InvalidFid, nil)
			return
		}
	}

	ok := false
	if format == "" {
		format, ok = frecord.GetFileFormat(fid)
		if !ok {
			recordInfo, err := f.ParsingTraceFile(fid)
			if err != nil {
				format, err = CheckFileType(f.Chainer, fid, c.Request.Header.Get(HTTPHeader_Account))
				if err != nil {
					if err.Error() == ERR_FileNotFound {
						f.Logopen("err", clientIp+" CheckFileType: "+err.Error())
						ReturnJSON(c, 400, ERR_FileNotFound, nil)
						return
					}
					f.Logopen("err", clientIp+" CheckFileType: "+err.Error())
					ReturnJSON(c, 403, ERR_RPCConnection, nil)
					return
				}
				frecord.AddToFileRecord(fid, format)
			} else {
				format = strings.ToLower(filepath.Ext(recordInfo.FileName))
				frecord.AddToFileRecord(fid, format)
			}
		}
	}

	contenttype, ok := contentType.Load(format)
	if !ok {
		contenttype = "text/plain"
	}

	f.Logopen("info", clientIp+" open file: "+fid+" format: "+format+" Range: "+rgn)

	size, fpath, err := FindLocalFile(fid, f.GetFileDir(), f.GetStoringDir())
	if err == nil {
		if rgn != "" {
			f.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from local by range", clientIp, fid))
			err = ReturnFileRangeStream(c, rgn, contenttype.(string), fpath)
			if err != nil {
				f.Logopen("err", err.Error())
			}
			return
		}
		fd, err := os.Open(fpath)
		if err != nil {
			f.Logopen("info", clientIp+" open the file from local, open file failed: "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}
		defer fd.Close()
		f.AccessFile(fpath)
		f.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from local", clientIp, fid))
		ReturnFileStream(c, fd, fid, contenttype.(string), format, int64(size))
		return
	}

	fmeta, err := f.QueryFile(fid, -1)
	if err != nil {
		f.Logdown("err", clientIp+" QueryFile failed: "+err.Error())
		ReturnJSON(c, 404, ERR_NotFound, nil)
		return
	}

	fpath = filepath.Join(f.GetFileDir(), fid)
	size, err = FindFileFromGW(f.Chainer, fid, fpath)
	if err == nil {
		if size != fmeta.FileSize.Uint64() {
			f.Logdown("info", clientIp+" the file size from gateway not equal chain")
			ReturnJSON(c, 404, ERR_NotFound, nil)
			return
		}
		if rgn != "" {
			f.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from gw by range", clientIp, fid))
			err = ReturnFileRangeStream(c, rgn, contenttype.(string), fpath)
			if err != nil {
				f.Logopen("err", err.Error())
			}
			return
		}
		fd, err := os.Open(fpath)
		if err != nil {
			f.Logopen("info", clientIp+" open the file from local, open file failed: "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}
		defer fd.Close()
		f.AccessFile(fpath)
		f.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from gw", clientIp, fid))
		ReturnFileStream(c, fd, fid, contenttype.(string), format, int64(size))
		return
	}

	fpath, err = process.Retrievefile(f.Chainer, fmeta, fid, f.GetFileDir(), cipher)
	if err != nil {
		f.Logdown("info", clientIp+" process.Retrievefile: "+err.Error())
		ReturnJSON(c, 404, ERR_NotFound, nil)
		return
	}
	if rgn != "" {
		f.AccessFile(fpath)
		f.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from miner by range", clientIp, fid))
		err = ReturnFileRangeStream(c, rgn, contenttype.(string), fpath)
		if err != nil {
			f.Logopen("err", err.Error())
		}
		return
	}
	fd, err := os.Open(fpath)
	if err != nil {
		f.Logopen("info", clientIp+" open the file from local, open file failed: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	defer fd.Close()
	f.AccessFile(fpath)
	f.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from gw", clientIp, fid))
	ReturnFileStream(c, fd, fid, contenttype.(string), format, int64(size))
	return
}

func (f *FileHandler) DownloadFileHandle(c *gin.Context) {
	fid := c.Param(HTTP_ParameterName_Fid)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	f.Logdown("info", clientIp+" download the file: "+fid)

	size, fpath, err := FindLocalFile(fid, f.GetFileDir(), f.GetStoringDir())
	if err == nil {
		fd, err := os.Open(fpath)
		if err != nil {
			f.Logdown("info", clientIp+" download the file from local, open file failed: "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}
		defer fd.Close()
		f.AccessFile(fpath)
		f.Logdown("info", clientIp+" download the file from local: "+fid)
		c.DataFromReader(http.StatusOK, int64(size), "application/octet-stream", fd, nil)
		return
	}

	fmeta, err := f.QueryFile(fid, -1)
	if err != nil {
		f.Logdown("err", clientIp+" QueryFile failed: "+err.Error())
		ReturnJSON(c, 404, ERR_NotFound, nil)
		return
	}

	fpath = filepath.Join(f.GetFileDir(), fid)
	size, err = FindFileFromGW(f.Chainer, fid, fpath)
	if err == nil {
		if size != fmeta.FileSize.Uint64() {
			f.Logdown("info", clientIp+" the file size from gateway not equal chain")
			ReturnJSON(c, 404, ERR_NotFound, nil)
			return
		}
		fd, err := os.Open(fpath)
		if err != nil {
			f.Logdown("info", clientIp+" "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}
		defer fd.Close()
		f.AccessFile(fpath)
		f.Logdown("info", clientIp+" download the file from gateway: "+fid)
		c.DataFromReader(http.StatusOK, int64(size), "application/octet-stream", fd, nil)
		return
	}

	fpath, err = process.Retrievefile(f.Chainer, fmeta, fid, f.GetFileDir(), cipher)
	if err != nil {
		f.Logdown("info", clientIp+" process.Retrievefile: "+err.Error())
		ReturnJSON(c, 404, ERR_NotFound, nil)
		return
	}

	fd, err := os.Open(fpath)
	if err != nil {
		f.Logdown("info", clientIp+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	defer fd.Close()
	f.AccessFile(fpath)
	f.Logdown("info", clientIp+" download the file from miner: "+fid)
	c.DataFromReader(http.StatusOK, int64(size), "application/octet-stream", fd, nil)
}

func (f *FileHandler) DeleteFileHandle(c *gin.Context) {
	defer c.Request.Body.Close()

	clientIp := c.Request.Header.Get(HTTPHeader_X_Forwarded_For)
	if clientIp == "" {
		clientIp = c.ClientIP()
	}
	fid := c.Param(HTTP_ParameterName_Fid)
	f.Logdel("info", utils.StringBuilder(400, clientIp, fid))

	err := CheckChainSt(f.Chainer, c)
	if err != nil {
		f.Logput("err", clientIp+" CheckChainSt: "+err.Error())
		return
	}

	pkeystr, ok := c.Get("publickey")
	if !ok {
		f.Logput("err", clientIp+" c.Get(publickey) failed")
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	pkey, err := hex.DecodeString(fmt.Sprintf("%v", pkeystr))
	if err != nil {
		f.Logput("err", clientIp+" hex.DecodeString "+fmt.Sprintf("%v", pkeystr)+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	if !sutils.CompareSlice(pkey, f.GetSignatureAccPulickey()) {
		err = CheckAuthorize(f.Chainer, c, pkey)
		if err != nil {
			f.Logput("err", clientIp+" CheckAuthorize: "+err.Error())
			return
		}
	}

	blockHash, err := f.DeleteFile(pkey, fid)
	if err != nil {
		f.Logdel("err", clientIp+" DeleteFile failed: "+err.Error())
		c.JSON(http.StatusBadRequest, err.Error())
		ReturnJSON(c, 400, ERR_SystemErr, nil)
		return
	}
	f.Logdel("info", clientIp+" DeleteFile suc: "+blockHash)
	ReturnJSON(c, 200, MSG_OK, map[string]string{"block hash": blockHash})
	_, err = f.QueryFile(fid, -1)
	if err != nil {
		if errors.Is(err, chain.ERR_RPC_EMPTY_VALUE) {
			data, err := f.ParsingTraceFile(fid)
			if err == nil {
				for _, segment := range data.Segment {
					for _, fragment := range segment.FragmentHash {
						os.Remove(fragment)
					}
				}
			}
			os.Remove(filepath.Join(f.GetFileDir(), fid))
		}
	}
}

func (f *FileHandler) UploadFormFileHandle(c *gin.Context) {
	defer c.Request.Body.Close()

	clientIp := c.Request.Header.Get(HTTPHeader_X_Forwarded_For)
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	freeSpace, _ := utils.GetDirFreeSpace(f.GetRootDir())
	if freeSpace < 10*1024*1024*1024 {
		f.Logput("err", fmt.Sprintf("insufficient server space: %d", freeSpace))
		ReturnJSON(c, 500, "Server space is insufficient, please try again later", nil)
		return
	}

	err := CheckChainSt(f.Chainer, c)
	if err != nil {
		f.Logput("err", clientIp+" CheckChainSt: "+err.Error())
		return
	}

	account := c.Request.Header.Get(HTTPHeader_Account)
	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)
	territoryName := c.Request.Header.Get(HTTPHeader_Territory)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	shuntminers := c.Request.Header.Values(HTTPHeader_Miner)
	longitudes := c.Request.Header.Values(HTTPHeader_Longitude)
	latitudes := c.Request.Header.Values(HTTPHeader_Latitude)
	filename := c.Request.Header.Get(HTTPHeader_Filename)
	f.Logput("info", utils.StringBuilder(400, clientIp, account, ethAccount, territoryName, cipher))
	shuntminerslength := len(shuntminers)
	if shuntminerslength > 0 {
		f.Logput("info", fmt.Sprintf("shuntminers: %d, %v", shuntminerslength, shuntminers))
	}
	points, err := coordinate.ConvertToRange(longitudes, latitudes)
	if err != nil {
		f.Logput("err", clientIp+" "+err.Error())
	}

	pkeystr, ok := c.Get("publickey")
	if !ok {
		f.Logput("err", clientIp+" c.Get(publickey) failed")
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	pkey, err := hex.DecodeString(fmt.Sprintf("%v", pkeystr))
	if err != nil {
		f.Logput("err", clientIp+" hex.DecodeString "+fmt.Sprintf("%v", pkeystr)+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	if !sutils.CompareSlice(pkey, f.GetSignatureAccPulickey()) {
		err = CheckAuthorize(f.Chainer, c, pkey)
		if err != nil {
			f.Logput("err", clientIp+" CheckAuthorize: "+err.Error())
			return
		}
	}

	territorySpace, err := CheckTerritory(f.Chainer, c, pkey, territoryName)
	if err != nil {
		f.Logput("err", clientIp+" CheckTerritory: "+err.Error())
		return
	}

	cacheDir, fpath, err := CreateTmpPath(c, f.GetTmpDir(), account)
	if err != nil {
		f.Logput("err", clientIp+" CreateTmpPath: "+err.Error())
		return
	}

	defer os.Remove(fpath)

	f.Logput("info", clientIp+" tmp file: "+fpath)

	fname, length, err := saveFormFile(c, fpath, filename)
	if err != nil {
		os.RemoveAll(cacheDir)
		f.Logput("err", clientIp+" saveFormFile: "+err.Error())
		return
	}
	actureSpace := calcActualSpace(uint64(length))
	if territorySpace < actureSpace {
		os.RemoveAll(cacheDir)
		f.Logput("err", clientIp+ERR_InsufficientTerritorySpace)
		ReturnJSON(c, 400, fmt.Sprintf("remaining space in the territory is less than %d", actureSpace), nil)
		return
	}

	segment, fid, err := process.FullProcessing(fpath, cipher, cacheDir)
	if err != nil {
		os.RemoveAll(cacheDir)
		f.Logput("err", clientIp+" FullProcessing: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	f.Logput("info", clientIp+" fid: "+fid)

	duplicate, err := checkDuplicate(f.Chainer, c, fid, pkey)
	if err != nil {
		os.RemoveAll(cacheDir)
		f.Logput("err", clientIp+" checkDuplicate: "+err.Error())
		return
	}

	newPath := filepath.Join(f.GetFileDir(), fid)
	err = os.Rename(fpath, newPath)
	if err != nil {
		os.RemoveAll(cacheDir)
		f.Logput("err", clientIp+" Rename: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	f.AccessFile(newPath)
	frecord.AddToFileRecord(fid, filepath.Ext(fname))

	_, err = os.Stat(newPath)
	if err != nil {
		os.RemoveAll(cacheDir)
		f.Logput("err", clientIp+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	f.Logput("info", clientIp+" new file path: "+newPath)

	switch duplicate {
	case Duplicate1:
		blockhash, err := f.PlaceStorageOrder(fid, fname, territoryName, segment, pkey, uint64(length))
		if err != nil {
			os.Remove(newPath)
			os.RemoveAll(cacheDir)
			f.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}
		f.Logput("info", clientIp+" duplicate file: "+fid+" storage order hash: "+blockhash)
		ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
		return
	case Duplicate2:
		os.RemoveAll(cacheDir)
		f.Logput("info", clientIp+" duplicate file: "+fid)
		ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
		return
	}

	err = f.AddToTraceFile(fid, tracker.TrackerInfo{
		Segment:       segment,
		Owner:         pkey,
		ShuntMiner:    shuntminers,
		Points:        points,
		Fid:           fid,
		FileName:      fname,
		TerritoryName: territoryName,
		CacheDir:      cacheDir,
		Cipher:        cipher,
		FileSize:      uint64(length),
	})
	if err != nil {
		os.Remove(newPath)
		os.RemoveAll(cacheDir)
		f.Logput("err", clientIp+" AddToTraceFile: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	blockhash, err := f.PlaceStorageOrder(fid, fname, territoryName, segment, pkey, uint64(length))
	if err != nil {
		f.DeleteTraceFile(fid)
		os.Remove(newPath)
		os.RemoveAll(cacheDir)
		f.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	f.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
}

func calcActualSpace(size uint64) uint64 {
	minSpace := chain.NumberOfDataCopies * chain.SegmentSize
	if size <= uint64(minSpace) {
		return uint64(minSpace)
	}
	count := size / chain.SegmentSize
	if size%chain.SegmentSize != 0 {
		count++
	}
	return count * chain.SegmentSize * chain.NumberOfDataCopies
}

func checkDuplicate(cli chain.Chainer, c *gin.Context, fid string, pkey []byte) (DuplicateType, error) {
	var err error
	var fmeta chain.FileMetadata
	for i := 0; i < 3; i++ {
		fmeta, err = cli.QueryFile(fid, -1)
		if err != nil {
			if strings.Contains(err.Error(), chain.ERR_RPC_CONNECTION.Error()) {
				time.Sleep(time.Second * 6)
				continue
			}
			if !errors.Is(err, chain.ERR_RPC_EMPTY_VALUE) {
				ReturnJSON(c, 500, ERR_SystemErr, nil)
				return Duplicate0, err
			}
			return Duplicate0, nil
		}
	}
	for _, v := range fmeta.Owner {
		if sutils.CompareSlice(v.User[:], pkey) {
			return Duplicate2, nil
		}
	}
	return Duplicate1, nil
}

func saveFormFile(c *gin.Context, file string, name string) (string, int64, error) {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if err != nil {
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return "", 0, err
	}
	defer f.Close()
	formfile, fileHeder, err := c.Request.FormFile("file")
	if err != nil {
		ReturnJSON(c, 400, err.Error(), nil)
		return "", 0, err
	}

	if name == "" {
		name = fileHeder.Filename
	}

	if strings.Contains(name, "%") {
		name, err = url.PathUnescape(name)
		if err != nil {
			name = fileHeder.Filename
		}
	}
	if len(name) > int(chain.MaxBucketNameLength) {
		ReturnJSON(c, 400, ERR_FileNameTooLang, nil)
		return "", 0, errors.New(ERR_FileNameTooLang)
	}
	if len(name) < int(chain.MinBucketNameLength) {
		ReturnJSON(c, 400, ERR_FileNameTooShort, nil)
		return "", 0, errors.New(ERR_FileNameTooShort)
	}

	length, err := io.Copy(f, formfile)
	if err != nil {
		ReturnJSON(c, 400, ERR_ReceiveData, nil)
		return name, 0, err
	}
	return name, length, nil
}

func (f *FileHandler) DownloadFragmentHandle(c *gin.Context) {
	fid := c.Param(HTTP_ParameterName_Fid)
	fid, ok := c.GetQuery("fid")
	if !ok {
		ReturnJSON(c, 400, "invalid fid", nil)
		return
	}

	fragmentHash, ok := c.GetQuery("fragment")
	if !ok {
		ReturnJSON(c, 400, "invalid fragment", nil)
		return
	}

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	cacheDir := filepath.Join(f.GetTmpDir(), fid, fragmentHash)
	os.MkdirAll(cacheDir, 0755)
	defer os.RemoveAll(cacheDir)

	_, fpath, err := FindLocalFile(fid, f.GetFileDir(), f.GetStoringDir())
	if err == nil {
		segment, fid, err := process.FullProcessing(fpath, "", cacheDir)
		if err == nil {
			for i := 0; i < len(segment); i++ {
				for j := 0; j < len(segment[i].FragmentHash); j++ {
					if fragmentHash == filepath.Base(segment[i].FragmentHash[j]) {
						fd, err := os.Open(segment[i].FragmentHash[j])
						if err == nil {
							defer fd.Close()
							f.AccessFile(fpath)
							f.Logdown("info", clientIp+" download the file from local: "+fid)
							c.DataFromReader(http.StatusOK, chain.FragmentSize, "application/octet-stream", fd, nil)
							return
						}
					}
				}
			}
		}
	}

	fmeta, err := f.QueryFile(fid, -1)
	if err != nil {
		f.Logdown("err", clientIp+" QueryFile failed: "+err.Error())
		ReturnJSON(c, 404, ERR_NotFound, nil)
		return
	}

	fpath, err = process.Retrievefile(f.Chainer, fmeta, fid, f.GetFileDir(), "")
	if err != nil {
		f.Logdown("info", clientIp+" process.Retrievefile: "+err.Error())
		ReturnJSON(c, 404, ERR_NotFound, nil)
		return
	}

	segment, fid, err := process.FullProcessing(fpath, "", cacheDir)
	if err == nil {
		for i := 0; i < len(segment); i++ {
			for j := 0; j < len(segment[i].FragmentHash); j++ {
				if fragmentHash == segment[i].FragmentHash[j] {
					fd, err := os.Open(segment[i].FragmentHash[j])
					if err == nil {
						defer fd.Close()
						f.AccessFile(fpath)
						f.Logdown("info", clientIp+" download the file from local: "+fid)
						c.DataFromReader(http.StatusOK, chain.FragmentSize, "application/octet-stream", fd, nil)
						return
					}
				}
			}
		}
	}

	ReturnJSON(c, 404, ERR_NotFound, nil)
	return
}
