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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

type MultiFormFiles struct {
	SegmentDataInfo []chain.SegmentDataInfo `json:"-"`
	Fapth           string                  `json:"-"`
	Name            string                  `json:"name"`
	Fid             string                  `json:"fid"`
	Result          string                  `json:"result"`
	Reason          string                  `json:"reason"`
	Size            int64                   `json:"size"`
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

	cacheDir, _, err := CreateTmpPath(c, f.GetTmpDir(), account)
	if err != nil {
		f.Logput("err", clientIp+" CreateTmpPath: "+err.Error())
		return
	}

	files, err := saveFormFiles(c, cacheDir)
	if err != nil {
		f.Logput("err", clientIp+" saveFormFiles: "+err.Error())
		ReturnJSON(c, 400, err.Error(), nil)
		return
	}

	length := len(files)
	totalActualSpace := uint64(0)
	for i := 0; i < length; i++ {
		if files[i].Result == "failed" {
			continue
		}
		totalActualSpace += calcActualSpace(uint64(files[i].Size))
	}

	if territorySpace < totalActualSpace {
		f.Logput("err", clientIp+ERR_InsufficientTerritorySpace)
		ReturnJSON(c, 400, ERR_InsufficientTerritorySpace, nil)
		return
	}

	for i := 0; i < length; i++ {
		if files[i].Result == "failed" {
			continue
		}
		files[i].SegmentDataInfo, files[i].Fid, err = process.FullProcessing(files[i].Fapth, cipher, cacheDir)
		if err != nil {
			files[i].Fid = ""
			files[i].Result = "failed"
			files[i].Reason = "failed to calculate fid"
			continue
		}
		f.Logput("info", clientIp+" one of the fids is: "+files[i].Fid)
		duplicate, err := checkDuplicate(f.Chainer, c, files[i].Fid, pkey)
		if err != nil {
			f.Logput("err", clientIp+" checkDuplicate: "+err.Error())
			files[i].Fid = ""
			files[i].Result = "failed"
			files[i].Reason = "checkDuplicate: " + err.Error()
			continue
		}

		newPath := filepath.Join(f.GetFileDir(), files[i].Fid)
		err = os.Rename(files[i].Fapth, newPath)
		if err != nil {
			f.Logput("err", clientIp+" Rename: "+err.Error())
			files[i].Fid = ""
			files[i].Result = "failed"
			files[i].Reason = "Rename: " + err.Error()
			continue
		}

		_, err = os.Stat(newPath)
		if err != nil {
			f.Logput("err", clientIp+" "+err.Error())
			files[i].Fid = ""
			files[i].Result = "failed"
			files[i].Reason = "Rename: " + err.Error()
			continue
		}

		f.AccessFile(newPath)
		frecord.AddToFileRecord(files[i].Fid, filepath.Ext(files[i].Name))

		f.Logput("info", clientIp+" new file path: "+newPath)

		switch duplicate {
		case Duplicate1:
			blockhash, err := f.PlaceStorageOrder(files[i].Fid, files[i].Name, territoryName, files[i].SegmentDataInfo, pkey, uint64(files[i].Size))
			if err != nil {
				f.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
				files[i].Fid = ""
				files[i].Result = "failed"
				files[i].Reason = "PlaceStorageOrder: " + err.Error()
				continue
			}
			f.Logput("info", clientIp+" duplicate file: "+files[i].Fid+" storage order hash: "+blockhash)
			continue
		case Duplicate2:
			f.Logput("info", clientIp+" duplicate file: "+files[i].Fid)
			continue
		}

		err = f.AddToTraceFile(files[i].Fid, tracker.TrackerInfo{
			Segment:       files[i].SegmentDataInfo,
			Owner:         pkey,
			ShuntMiner:    shuntminers,
			Points:        points,
			Fid:           files[i].Fid,
			FileName:      files[i].Name,
			TerritoryName: territoryName,
			CacheDir:      cacheDir,
			Cipher:        cipher,
			FileSize:      uint64(length),
		})
		if err != nil {
			f.Logput("err", clientIp+" AddToTraceFile: "+err.Error())
			files[i].Fid = ""
			files[i].Result = "failed"
			files[i].Reason = ERR_SystemErr
			continue
		}

		blockhash, err := f.PlaceStorageOrder(files[i].Fid, files[i].Name, territoryName, files[i].SegmentDataInfo, pkey, uint64(files[i].Size))
		if err != nil {
			f.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
			files[i].Fid = ""
			files[i].Result = "failed"
			files[i].Reason = "PlaceStorageOrder: " + err.Error()
			continue
		}
		f.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	}

	ReturnJSON(c, 200, MSG_OK, files)
}

func saveFormFiles(c *gin.Context, cacheDir string) ([]MultiFormFiles, error) {
	multiFormFiles := make([]MultiFormFiles, 0)
	// max per file size is 100MiB
	err := c.Request.ParseMultipartForm(100 << 20)
	if err != nil {
		return multiFormFiles, err
	}

	formFile := c.Request.MultipartForm.File["file"]
	if len(formFile) == 0 {
		return multiFormFiles, errors.New("no such file")
	}

	fpath := ""
	// save files
	for _, file := range formFile {
		fpath = filepath.Join(cacheDir, fmt.Sprintf("%v", time.Now().UnixNano()))
		time.Sleep(time.Millisecond)
		err = c.SaveUploadedFile(file, fpath)
		if err != nil {
			os.Remove(fpath)
			multiFormFiles = append(multiFormFiles, MultiFormFiles{
				Name:   file.Filename,
				Result: "failed",
				Reason: err.Error(),
				Size:   file.Size,
			})
			continue
		}

		filename := file.Filename
		if strings.Contains(filename, "%") {
			filename, err = url.PathUnescape(filename)
			if err != nil {
				filename = file.Filename
			}
		}
		if len(filename) > int(chain.MaxBucketNameLength) {
			os.Remove(fpath)
			multiFormFiles = append(multiFormFiles, MultiFormFiles{
				Name:   file.Filename,
				Result: "failed",
				Reason: ERR_FileNameTooLang,
				Size:   file.Size,
			})
			continue
		}
		if len(filename) < int(chain.MinBucketNameLength) {
			os.Remove(fpath)
			multiFormFiles = append(multiFormFiles, MultiFormFiles{
				Name:   file.Filename,
				Result: "failed",
				Reason: ERR_FileNameTooShort,
				Size:   file.Size,
			})
			continue
		}

		multiFormFiles = append(multiFormFiles, MultiFormFiles{
			Fapth:  fpath,
			Name:   file.Filename,
			Result: "success",
			Size:   file.Size,
		})
	}
	return multiFormFiles, nil
}
