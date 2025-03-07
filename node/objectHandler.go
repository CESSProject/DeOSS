/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

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

type ObjectHandler struct {
	chain.Chainer
	workspace.Workspace
	tracker.Tracker
	logger.Logger
	*confile.Config
	*rate.Limiter
	*lru.LRUCache
}

func NewObjectHandler(cli chain.Chainer, track tracker.Tracker, ws workspace.Workspace, lg logger.Logger, cfg *confile.Config, lru *lru.LRUCache) *ObjectHandler {
	return &ObjectHandler{Chainer: cli, Tracker: track, Workspace: ws, Logger: lg, Config: cfg, Limiter: rate.NewLimiter(rate.Every(chain.BlockInterval), 20), LRUCache: lru}
}

func (o *ObjectHandler) RegisterRoutes(server *gin.Engine) {
	objectgroup := server.Group("/object")
	objectgroup.Use(
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
			if !CheckPermissionsMdl(fmt.Sprintf("%v", acc), o.Config.Access.Mode, o.Config.User.Account, o.Config.Access.Account) {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			ctx.Next()
		},
	)

	objectgroup.PUT(fmt.Sprintf("/:%s", HTTP_ParameterName), o.UploadObjectHandle)
}

func (o *ObjectHandler) UploadObjectHandle(c *gin.Context) {
	defer c.Request.Body.Close()

	clientIp := c.Request.Header.Get(HTTPHeader_X_Forwarded_For)
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	err := CheckChainSt(o.Chainer, c)
	if err != nil {
		o.Logput("err", clientIp+" CheckChainSt: "+err.Error())
		return
	}

	filename := c.Param(HTTP_ParameterName)
	account := c.Request.Header.Get(HTTPHeader_Account)
	territoryName := c.Request.Header.Get(HTTPHeader_Territory)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)
	shuntminers := c.Request.Header.Values(HTTPHeader_Miner)
	longitudes := c.Request.Header.Values(HTTPHeader_Longitude)
	latitudes := c.Request.Header.Values(HTTPHeader_Latitude)
	o.Logput("info", utils.StringBuilder(400, clientIp, account, territoryName, cipher))

	shuntminerslength := len(shuntminers)
	if shuntminerslength > 0 {
		o.Logput("info", fmt.Sprintf("shuntminers: %d, %v", shuntminerslength, shuntminers))
	}
	points, err := coordinate.ConvertToRange(longitudes, latitudes)
	if err != nil {
		o.Logput("err", clientIp+" "+err.Error())
	}

	pkeystr, ok := c.Get("publickey")
	if !ok {
		o.Logput("err", clientIp+" c.Get(publickey) failed")
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	pkey, err := hex.DecodeString(fmt.Sprintf("%v", pkeystr))
	if err != nil {
		o.Logput("err", clientIp+" hex.DecodeString "+fmt.Sprintf("%v", pkeystr)+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	if !sutils.CompareSlice(pkey, o.GetSignatureAccPulickey()) {
		err = CheckAuthorize(o.Chainer, c, pkey)
		if err != nil {
			o.Logput("err", clientIp+" CheckAuthorize: "+err.Error())
			return
		}
	}

	territorySpace, err := CheckTerritory(o.Chainer, c, pkey, territoryName)
	if err != nil {
		o.Logput("err", clientIp+" CheckTerritory: "+err.Error())
		return
	}

	if filename == "" {
		filename = "object"
	}

	cacheDir, fpath, err := CreateTmpPath(c, o.GetTmpDir(), account)
	if err != nil {
		o.Logput("err", clientIp+" CreateTmpPath: "+err.Error())
		return
	}

	o.Logput("info", clientIp+" tmp file: "+fpath)

	length, err := saveObjectToFile(c, fpath)
	if err != nil {
		o.Logput("err", clientIp+" saveObjectToFile: "+err.Error())
		return
	}

	if territorySpace < calcActualSpace(uint64(length)) {
		o.Logput("err", clientIp+ERR_InsufficientTerritorySpace)
		ReturnJSON(c, 400, ERR_InsufficientTerritorySpace, nil)
		return
	}

	segmentInfo, fid, err := process.FullProcessing(fpath, cipher, cacheDir)
	if err != nil {
		o.Logput("err", clientIp+" FullProcessing: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	o.Logput("info", clientIp+" fid: "+fid)

	duplicate, err := checkDuplicate(o.Chainer, c, fid, pkey)
	if err != nil {
		o.Logput("err", clientIp+" checkDuplicate: "+err.Error())
		return
	}

	newPath := filepath.Join(o.GetFileDir(), fid)
	err = os.Rename(fpath, newPath)
	if err != nil {
		o.Logput("err", clientIp+" Rename: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	o.AccessFile(newPath)
	frecord.AddToFileRecord(fid, filepath.Ext(filename))

	_, err = os.Stat(newPath)
	if err != nil {
		o.Logput("err", clientIp+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	o.Logput("info", clientIp+" new file path: "+newPath)

	switch duplicate {
	case Duplicate1:
		blockhash, err := o.PlaceStorageOrder(fid, filename, territoryName, segmentInfo, pkey, uint64(length))
		if err != nil {
			o.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}
		o.Logput("info", clientIp+" duplicate file: "+fid+" storage order hash: "+blockhash)
		ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
		return
	case Duplicate2:
		o.Logput("info", clientIp+" duplicate file: "+fid)
		ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
		return
	}

	err = o.AddToTraceFile(fid, tracker.TrackerInfo{
		Segment:       segmentInfo,
		Owner:         pkey,
		ShuntMiner:    shuntminers,
		Points:        points,
		Fid:           fid,
		FileName:      filename,
		TerritoryName: territoryName,
		CacheDir:      cacheDir,
		Cipher:        cipher,
		FileSize:      uint64(length),
	})
	if err != nil {
		o.Logput("err", clientIp+" AddToTraceFile: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	blockhash, err := o.PlaceStorageOrder(fid, filename, territoryName, segmentInfo, pkey, uint64(length))
	if err != nil {
		o.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	o.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
}

func saveObjectToFile(c *gin.Context, file string) (int64, error) {
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if err != nil {
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return 0, err
	}
	defer f.Close()
	length, err := io.Copy(f, c.Request.Body)
	if err != nil {
		ReturnJSON(c, 400, ERR_ReceiveData, nil)
		return 0, err
	}
	err = f.Sync()
	if err != nil {
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return 0, err
	}
	return length, nil
}
