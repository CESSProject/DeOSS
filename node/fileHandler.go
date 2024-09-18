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
	"time"

	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/tracker"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/common/workspace"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
)

type FileHandler struct {
	chain.Chainer
	workspace.Workspace
	tracker.Tracker
	logger.Logger
	*confile.Config
}

func NewFileHandler(cli chain.Chainer, track tracker.Tracker, ws workspace.Workspace, lg logger.Logger) *FileHandler {
	return &FileHandler{Chainer: cli, Tracker: track, Workspace: ws, Logger: lg}
}

func (f *FileHandler) RegisterRoutes(server *gin.Engine) {
	filegroup := server.Group("/file")
	filegroup.Use(
		func(ctx *gin.Context) {
			acc, pk, ok := VerifySignatureMdl(ctx)
			if !ok {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
			ctx.Set("account", acc)
			ctx.Set("publickey", hex.EncodeToString(pk))
			ctx.Next()
		},
		func(ctx *gin.Context) {
			acc, ok := ctx.Get("account")
			if !ok {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
			if !CheckPermissionsMdl(fmt.Sprintf("%v", acc), f.Config.Access.Mode, f.Config.User.Account, f.Config.Access.Account) {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
			ctx.Next()
		},
	)
	filegroup.PUT("", f.PutFormFile)
}

func (f *FileHandler) PutFormFile(c *gin.Context) {
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
	bucketName := c.Request.Header.Get(HTTPHeader_Bucket)
	territoryName := c.Request.Header.Get(HTTPHeader_Territory)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	shuntminers := c.Request.Header.Values(HTTPHeader_Miner)
	longitudes := c.Request.Header.Values(HTTPHeader_Longitude)
	latitudes := c.Request.Header.Values(HTTPHeader_Latitude)
	f.Logput("info", utils.StringBuilder(400, clientIp, account, ethAccount, bucketName, territoryName, cipher))
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

	if !chain.CheckBucketName(bucketName) {
		f.Logput("err", clientIp+" CheckBucketName failed: "+bucketName)
		ReturnJSON(c, 400, ERR_HeaderFieldBucketName, nil)
		return
	}

	err = CheckAuthorize(f.Chainer, c, pkey)
	if err != nil {
		f.Logput("err", clientIp+" CheckAuthorize: "+err.Error())
		return
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

	_, err = os.Stat(newPath)
	if err != nil {
		f.Logput("err", clientIp+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	f.Logput("info", clientIp+" new file path: "+newPath)

	switch duplicate {
	case Duplicate1:
		blockhash, err := f.PlaceStorageOrder(fid, fname, bucketName, territoryName, segment, pkey, uint64(length))
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
		BucketName:    bucketName,
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

	blockhash, err := f.PlaceStorageOrder(fid, fname, bucketName, territoryName, segment, pkey, uint64(length))
	if err != nil {
		f.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	f.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
}

func calcActualSpace(size uint64) uint64 {
	count := size / chain.SegmentSize
	if size%chain.SegmentSize != 0 {
		count++
	}
	return count * chain.SegmentSize
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

func saveFormFile(c *gin.Context, file string) (string, int64, error) {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if err != nil {
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return "", 0, err
	}
	defer f.Close()
	formfile, fileHeder, err := c.Request.FormFile("file")
	if err != nil {
		ReturnJSON(c, 400, ERR_SystemErr, nil)
		return "", 0, err
	}
	filename := fileHeder.Filename
	if strings.Contains(filename, "%") {
		filename, err = url.PathUnescape(filename)
		if err != nil {
			filename = fileHeder.Filename
		}
	}
	if len(filename) > int(chain.MaxBucketNameLength) {
		ReturnJSON(c, 400, ERR_FileNameTooLang, nil)
		return "", 0, errors.New(ERR_FileNameTooLang)
	}
	if len(filename) < int(chain.MinBucketNameLength) {
		ReturnJSON(c, 400, ERR_FileNameTooShort, nil)
		return "", 0, errors.New(ERR_FileNameTooShort)
	}
	length, err := io.Copy(f, formfile)
	if err != nil {
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return filename, 0, err
	}
	return filename, length, nil
}
