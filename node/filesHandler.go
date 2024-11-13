/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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

type FilesHandler struct {
	chain.Chainer
	workspace.Workspace
	tracker.Tracker
	logger.Logger
	*confile.Config
	*rate.Limiter
	*lru.LRUCache
}

func NewFilesHandler(cli chain.Chainer, track tracker.Tracker, ws workspace.Workspace, lg logger.Logger, cfg *confile.Config, lru *lru.LRUCache) *FilesHandler {
	return &FilesHandler{Chainer: cli, Tracker: track, Workspace: ws, Logger: lg, Config: cfg, Limiter: rate.NewLimiter(rate.Every(time.Millisecond*10), 10), LRUCache: lru}
}

func (f *FilesHandler) RegisterRoutes(server *gin.Engine) {
	filegroup := server.Group("/files")
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
		f.UploadFormFilesHandle,
	)
}

func (f *FilesHandler) UploadFormFilesHandle(c *gin.Context) {
	defer c.Request.Body.Close()

	clientIp := c.Request.Header.Get(HTTPHeader_X_Forwarded_For)
	if clientIp == "" {
		clientIp = c.ClientIP()
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

	f.Logput("info", clientIp+" tmp file: "+fpath)

	fname, length, err := saveFormFile(c, fpath)
	if err != nil {
		f.Logput("err", clientIp+" saveFormFile: "+err.Error())
		return
	}

	if territorySpace < calcActualSpace(uint64(length)) {
		f.Logput("err", clientIp+ERR_InsufficientTerritorySpace)
		ReturnJSON(c, 400, ERR_InsufficientTerritorySpace, nil)
		return
	}

	segment, fid, err := process.FullProcessing(fpath, cipher, cacheDir)
	if err != nil {
		f.Logput("err", clientIp+" FullProcessing: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	f.Logput("info", clientIp+" fid: "+fid)

	duplicate, err := checkDuplicate(f.Chainer, c, fid, pkey)
	if err != nil {
		f.Logput("err", clientIp+" checkDuplicate: "+err.Error())
		return
	}

	newPath := filepath.Join(f.GetFileDir(), fid)
	err = os.Rename(fpath, newPath)
	if err != nil {
		f.Logput("err", clientIp+" Rename: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	f.AccessFile(newPath)
	frecord.AddToFileRecord(fid, filepath.Ext(fname))

	_, err = os.Stat(newPath)
	if err != nil {
		f.Logput("err", clientIp+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	f.Logput("info", clientIp+" new file path: "+newPath)

	switch duplicate {
	case Duplicate1:
		blockhash, err := f.PlaceStorageOrder(fid, fname, territoryName, segment, pkey, uint64(length))
		if err != nil {
			f.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}
		f.Logput("info", clientIp+" duplicate file: "+fid+" storage order hash: "+blockhash)
		ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
		return
	case Duplicate2:
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
		f.Logput("err", clientIp+" AddToTraceFile: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	blockhash, err := f.PlaceStorageOrder(fid, fname, territoryName, segment, pkey, uint64(length))
	if err != nil {
		f.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	f.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
}

type MultiFormFiles struct {
	file string
	name string
	size string
}

func saveFormFiles(c *gin.Context) ([]MultiFormFiles, error) {
	multiFormFiles := make([]MultiFormFiles, 0)

	// max per file siza is 100MiB
	err := c.Request.ParseMultipartForm(100 << 20)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to parse form"})
		return multiFormFiles, err
	}

	formFile := c.Request.MultipartForm.File["files"]
	if len(formFile) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No files uploaded"})
		return multiFormFiles, err
	}

	// save files
	for _, file := range formFile {
		// get files
		dst := filepath.Join("uploads", file.Filename)
		// create dir
		err := os.MkdirAll(filepath.Dir(dst), os.ModePerm)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create directory"})
			return multiFormFiles, err
		}
		// save to local
		err = c.SaveUploadedFile(file, dst)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save file %s", file.Filename)})
			return multiFormFiles, err
		}
	}

	// f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	// if err != nil {
	// 	ReturnJSON(c, 500, ERR_SystemErr, nil)
	// 	return "", 0, err
	// }
	// defer f.Close()
	// formfile, fileHeder, err := c.Request.FormFile("file")
	// if err != nil {
	// 	ReturnJSON(c, 400, ERR_SystemErr, nil)
	// 	return "", 0, err
	// }
	// filename := fileHeder.Filename
	// if strings.Contains(filename, "%") {
	// 	filename, err = url.PathUnescape(filename)
	// 	if err != nil {
	// 		filename = fileHeder.Filename
	// 	}
	// }
	// if len(filename) > int(chain.MaxBucketNameLength) {
	// 	ReturnJSON(c, 400, ERR_FileNameTooLang, nil)
	// 	return "", 0, errors.New(ERR_FileNameTooLang)
	// }
	// if len(filename) < int(chain.MinBucketNameLength) {
	// 	ReturnJSON(c, 400, ERR_FileNameTooShort, nil)
	// 	return "", 0, errors.New(ERR_FileNameTooShort)
	// }
	// length, err := io.Copy(f, formfile)
	// if err != nil {
	// 	ReturnJSON(c, 400, ERR_ReceiveData, nil)
	// 	return filename, 0, err
	// }
	return multiFormFiles, nil
}
