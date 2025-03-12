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
	"strconv"
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
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

type ResumeHandler struct {
	chain.Chainer
	workspace.Workspace
	tracker.Tracker
	logger.Logger
	*confile.Config
	*rate.Limiter
}

func NewResumeHandler(cli chain.Chainer, track tracker.Tracker, ws workspace.Workspace, lg logger.Logger, cfg *confile.Config) *ResumeHandler {
	return &ResumeHandler{Chainer: cli, Tracker: track, Workspace: ws, Logger: lg, Config: cfg, Limiter: rate.NewLimiter(rate.Every(time.Millisecond*10), 20)}
}

func (r *ResumeHandler) RegisterRoutes(server *gin.Engine) {
	resumegroup := server.Group("/resume")
	resumegroup.Use(
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
			if !CheckPermissionsMdl(fmt.Sprintf("%v", acc), r.Config.Access.Mode, r.Config.User.Account, r.Config.Access.Account) {
				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
					Code: http.StatusForbidden,
					Msg:  ERR_NoPermission,
				})
				return
			}
			ctx.Next()
		},
	)
	resumegroup.PUT(fmt.Sprintf("/:%s", HTTP_ParameterName), r.ResumeHandle)
}

func (r *ResumeHandler) ResumeHandle(c *gin.Context) {
	defer c.Request.Body.Close()

	account := c.Request.Header.Get(HTTPHeader_Account)
	clientIp := c.Request.Header.Get(HTTPHeader_X_Forwarded_For)
	if clientIp == "" {
		clientIp = c.ClientIP()
	}

	dir := filepath.Join(r.GetTmpDir(), account)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		r.Logput("err", clientIp+" MkdirAll: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	rangeHeader := c.GetHeader(HTTPHeader_Range)
	if rangeHeader == "" {
		r.Logput("err", clientIp+" "+ERR_MissingContentRange)
		ReturnJSON(c, 400, ERR_MissingContentRange, nil)
		return
	}

	rangeParts := strings.Split(rangeHeader, " ")
	if len(rangeParts) != 2 || !strings.HasPrefix(rangeParts[0], "bytes") {
		r.Logput("err", clientIp+" Invalid Content-Range format: "+rangeHeader)
		ReturnJSON(c, 400, ERR_IllegalContentRange, nil)
		return
	}

	rangeInfo := strings.Split(rangeParts[1], "/")
	if len(rangeInfo) != 2 {
		r.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		ReturnJSON(c, 400, ERR_IllegalContentRange, nil)
		return
	}

	total, err := strconv.ParseInt(rangeInfo[1], 10, 64)
	if err != nil {
		r.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		ReturnJSON(c, 400, ERR_IllegalContentRange, nil)
		return
	}

	byteRange := strings.Split(rangeInfo[0], "-")
	if len(byteRange) != 2 {
		r.Logput("err", clientIp+" Invalid byte range: "+rangeHeader)
		ReturnJSON(c, 400, ERR_IllegalContentRange, nil)
		return
	}

	start, err := strconv.ParseInt(byteRange[0], 10, 64)
	if err != nil || start < 0 {
		r.Logput("err", clientIp+" Invalid start range: "+rangeHeader)
		ReturnJSON(c, 400, ERR_IllegalContentRange, nil)
		return
	}

	filename := c.Param(HTTP_ParameterName)

	if start == 0 {
		r.Logput("info", utils.StringBuilder(400, clientIp, account, filename, rangeHeader))

		if !r.Limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusOK, RespType{
				Code: http.StatusForbidden,
				Msg:  ERR_ServerBusy,
			})
			return
		}

		err := CheckChainSt(r.Chainer, c)
		if err != nil {
			r.Logput("err", clientIp+" CheckChainSt: "+err.Error())
			return
		}

		err = CheckFilename(c, filename)
		if err != nil {
			r.Logput("err", clientIp+" CheckFilename: "+err.Error())
			return
		}

		pkeystr, ok := c.Get("publickey")
		if !ok {
			r.Logput("err", clientIp+" c.Get(publickey) failed")
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}

		pkey, err := hex.DecodeString(fmt.Sprintf("%v", pkeystr))
		if err != nil {
			r.Logput("err", clientIp+" hex.DecodeString "+fmt.Sprintf("%v", pkeystr)+" "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}

		if !sutils.CompareSlice(pkey, r.GetSignatureAccPulickey()) {
			err = CheckAuthorize(r.Chainer, c, pkey)
			if err != nil {
				r.Logput("err", clientIp+" CheckAuthorize: "+err.Error())
				return
			}
		}
	}

	fpath := filepath.Join(dir, fmt.Sprintf("%s-%s", filename, rangeInfo[1]))
	fd, err := os.OpenFile(fpath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		r.Logput("err", clientIp+" OpenFile: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	defer func() {
		if fd != nil {
			fd.Close()
		}
	}()

	fstat, err := fd.Stat()
	if err != nil {
		r.Logput("err", clientIp+" Stat: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	end, err := strconv.ParseInt(byteRange[1], 10, 64)
	if err != nil || end < start || end > total {
		// fmt.Println("start: ", start, "end: ", end, "total: ", total, "file_size: ", fstat.Size())
		r.Logput("err", clientIp+" Invalid end range: "+rangeHeader)
		ReturnJSON(c, 400, ERR_IllegalContentRange, nil)
		return
	}

	if start > fstat.Size() {
		r.Logput("err", clientIp+" Invalid start range: "+rangeHeader)
		ReturnJSON(c, 400, ERR_IllegalContentRange, nil)
		return
	}

	_, err = fd.Seek(start, io.SeekStart)
	if err != nil {
		r.Logput("err", clientIp+" f.Seek: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	length, err := io.Copy(fd, c.Request.Body)
	if err != nil && err != io.EOF {
		r.Logput("err", clientIp+" Copy: "+err.Error())
		ReturnJSON(c, 400, ERR_FailedToRecvData, nil)
		return
	}

	//fmt.Println("length: ", length)

	if length > (end - start + 1) {
		r.Logput("err", clientIp+"io. Copy(body)")
		ReturnJSON(c, 400, "received more file content", nil)
		return
	}

	if length < (end - start + 1) {
		r.Logput("err", clientIp+"io. Copy(body)")
		ReturnJSON(c, 400, "received less file content", nil)
		return
	}

	if end+1 < total {
		r.Logput("info", fmt.Sprintf("%s Received bytes: %s", clientIp, rangeHeader))
		c.Header("Content-Range", rangeHeader)
		c.JSON(http.StatusPermanentRedirect, nil)
		return
	}

	fd.Close()
	fd = nil

	r.Logput("info", fmt.Sprintf("%s Received bytes: %s\n", clientIp, rangeHeader))

	pkeystr, ok := c.Get("publickey")
	if !ok {
		r.Logput("err", clientIp+" c.Get(publickey) failed")
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	pkey, err := hex.DecodeString(fmt.Sprintf("%v", pkeystr))
	if err != nil {
		r.Logput("err", clientIp+" hex.DecodeString "+fmt.Sprintf("%v", pkeystr)+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	territoryName := c.Request.Header.Get(HTTPHeader_Territory)
	cipher := c.Request.Header.Get(HTTPHeader_Cipher)

	territorySpace, err := CheckTerritory(r.Chainer, c, pkey, territoryName)
	if err != nil {
		r.Logput("err", clientIp+" CheckTerritory: "+err.Error())
		return
	}

	if territorySpace < calcActualSpace(uint64(total)) {
		r.Logput("err", clientIp+ERR_InsufficientTerritorySpace)
		ReturnJSON(c, 400, ERR_InsufficientTerritorySpace, nil)
		return
	}

	shuntminers := c.Request.Header.Values(HTTPHeader_Miner)
	longitudes := c.Request.Header.Values(HTTPHeader_Longitude)
	latitudes := c.Request.Header.Values(HTTPHeader_Latitude)

	shuntminerslength := len(shuntminers)
	if shuntminerslength > 0 {
		r.Logput("info", fmt.Sprintf("shuntminers: %d, %v", shuntminerslength, shuntminers))
	}
	points, err := coordinate.ConvertToRange(longitudes, latitudes)
	if err != nil {
		r.Logput("err", clientIp+" "+err.Error())
	}

	uid := ""
	for {
		u, err := uuid.NewUUID()
		if err != nil {
			time.Sleep(time.Millisecond * 10)
			continue
		}
		uid = u.String()
		if uid != "" {
			break
		}
		time.Sleep(time.Millisecond * 10)
		continue
	}

	cacherDir := filepath.Join(r.GetTmpDir(), account, uid)

	segment, fid, err := process.FullProcessing(fpath, cipher, cacherDir)
	if err != nil {
		r.Logput("err", clientIp+" FullProcessing: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	r.Logput("info", clientIp+" fid: "+fid)

	duplicate, err := checkDuplicate(r.Chainer, c, fid, pkey)
	if err != nil {
		r.Logput("err", clientIp+" checkDuplicate: "+err.Error())
		return
	}

	newPath := filepath.Join(r.GetFileDir(), fid)
	err = os.Rename(fpath, newPath)
	if err != nil {
		r.Logput("err", clientIp+" Rename: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	_, err = os.Stat(newPath)
	if err != nil {
		r.Logput("err", clientIp+" "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	frecord.AddToFileRecord(fid, filepath.Ext(filename))

	r.Logput("info", clientIp+" new file path: "+newPath)

	switch duplicate {
	case Duplicate1:
		blockhash, err := r.PlaceStorageOrder(fid, filename, territoryName, segment, pkey, uint64(total))
		if err != nil {
			r.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
			ReturnJSON(c, 500, ERR_SystemErr, nil)
			return
		}
		r.Logput("info", clientIp+" duplicate file: "+fid+" storage order hash: "+blockhash)
		ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
		return
	case Duplicate2:
		r.Logput("info", clientIp+" duplicate file: "+fid)
		ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
		return
	}

	err = r.AddToTraceFile(fid, tracker.TrackerInfo{
		Segment:       segment,
		Owner:         pkey,
		ShuntMiner:    shuntminers,
		Points:        points,
		Fid:           fid,
		FileName:      filename,
		TerritoryName: territoryName,
		CacheDir:      cacherDir,
		Cipher:        cipher,
		FileSize:      uint64(total),
	})
	if err != nil {
		r.Logput("err", clientIp+" AddToTraceFile: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}

	blockhash, err := r.PlaceStorageOrder(fid, filename, territoryName, segment, pkey, uint64(total))
	if err != nil {
		r.Logput("err", clientIp+" PlaceStorageOrder: "+err.Error())
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return
	}
	r.Logput("info", clientIp+" uploaded suc and the storage order hash: "+blockhash)
	ReturnJSON(c, 200, MSG_OK, map[string]string{"fid": fid})
}
