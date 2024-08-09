/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/CESSProject/DeOSS/common/db"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/peerrecord"
	"github.com/CESSProject/DeOSS/common/trackfile"
	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/CESSProject/cess-go-tools/cacher"
	"github.com/CESSProject/cess-go-tools/scheduler"
	"github.com/CESSProject/p2p-go/core"
	"github.com/CESSProject/p2p-go/out"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Node struct {
	signkey   []byte
	trackLock *sync.RWMutex
	basespace string
	fileDir   string
	tmpDir    string
	logDir    string
	dbDir     string
	trackDir  string
	trackfile.TrackFile
	logger.Logger
	db.Cache
	peerrecord.PeerRecord
	cacher.FileCache
	scheduler.Selector
	*confile.Config
	*chain.ChainClient
	*core.PeerNode
	*gin.Engine
}

// New is used to build a node instance
func New() *Node {
	return &Node{
		trackLock:  new(sync.RWMutex),
		PeerRecord: peerrecord.NewPeerRecord(),
		TrackFile:  trackfile.NewTeeRecord(),
	}
}

// run
func (n *Node) Run() {
	gin.SetMode(n.Config.Application.Mode)
	n.Engine = gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	n.Engine.MaxMultipartMemory = MaxMemUsed
	n.Engine.Use(cors.New(config))

	n.Engine.GET("/version", n.Get_version)
	n.Engine.GET("/bucket", n.Get_bucket)
	n.Engine.GET(fmt.Sprintf("/metadata/:%s", HTTP_ParameterName_Fid), n.Get_metadata)
	n.Engine.GET(fmt.Sprintf("/download/:%s", HTTP_ParameterName_Fid), n.Download_file)
	n.Engine.GET(fmt.Sprintf("/canfiles/:%s", HTTP_ParameterName_Fid), n.GetCanFileHandle)
	n.Engine.GET(fmt.Sprintf("/open/:%s", HTTP_ParameterName_Fid), n.Preview_file)
	n.Engine.GET(fmt.Sprintf("/location/:%s", HTTP_ParameterName_Fid), n.Get_location)

	n.Engine.PUT("/bucket", n.Put_bucket)
	n.Engine.PUT("/file", n.Put_file)
	n.Engine.PUT("/object", n.Put_object)
	n.Engine.PUT("/chunks", n.PutChunksHandle)

	n.Engine.DELETE(fmt.Sprintf("/file/:%s", HTTP_ParameterName), n.Delete_file)
	n.Engine.DELETE(fmt.Sprintf("/bucket/:%s", HTTP_ParameterName), n.Delete_bucket)

	n.Engine.GET("/404", n.NotFound)

	// tasks
	go n.TaskMgt()

	out.Tip(fmt.Sprintf("Listening on port: %d", n.Config.Application.Port))
	err := n.Engine.Run(fmt.Sprintf(":%d", n.Config.Application.Port))
	if err != nil {
		log.Fatalf("err: %v", err)
	}
}

func (n *Node) Setup() error {
	var err error
	if n.Config == nil {
		return errors.New("setup: empty config")
	}
	n.signkey, err = sutils.CalcMD5(n.Config.Chain.Mnemonic)
	if err != nil {
		return errors.Wrap(err, "setup: ")
	}
	keyringPair, err := signature.KeyringPairFromSecret(n.Config.Chain.Mnemonic, 0)
	if err != nil {
		return errors.Wrap(err, "setup: ")
	}
	account, err := sutils.EncodePublicKeyAsCessAccount(keyringPair.PublicKey)
	if err != nil {
		return errors.Wrap(err, "setup: ")
	}
	n.basespace = filepath.Join(n.Application.Workspace, account, configs.NameSpace)

	err = n.creatDir(n.basespace)
	if err != nil {
		return errors.Wrap(err, "setup: ")
	}
	return nil
}

func (n *Node) GetBasespace() string {
	return n.basespace
}

func (n *Node) GetDBDir() string {
	return n.dbDir
}

func (n *Node) GetLogDir() string {
	return n.logDir
}

func (n *Node) creatDir(basespace string) error {
	n.fileDir = filepath.Join(basespace, "file")
	n.tmpDir = filepath.Join(basespace, "tmp")
	n.logDir = filepath.Join(basespace, "log")
	n.dbDir = filepath.Join(basespace, "db")
	n.trackDir = filepath.Join(basespace, "track")
	err := os.MkdirAll(n.fileDir, 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(n.tmpDir, 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(n.logDir, 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(n.dbDir, 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(n.trackDir, 0755)
	if err != nil {
		return err
	}
	return nil
}

func (n *Node) InitFileCache(exp time.Duration, maxSpace int64, cacheDir string) {
	n.FileCache = cacher.NewCacher(exp, maxSpace, cacheDir)
}

func (n *Node) InitNodeSelector(strategy string, nodeFilePath string, maxNodeNum int, maxTTL, flushInterval int64) error {
	var err error
	n.Selector, err = scheduler.NewNodeSelector(strategy, nodeFilePath, maxNodeNum, maxTTL, flushInterval)
	if err != nil {
		return err
	}
	//refresh the user-configured storage node list
	n.Selector.FlushlistedPeerNodes(scheduler.DEFAULT_TIMEOUT, n.GetDHTable())
	return nil
}

func (n *Node) WriteTrackFile(fid string, data []byte) error {
	if len(fid) != chain.FileHashLen {
		return errors.New("invalid fid")
	}
	var err error
	fpath := filepath.Join(n.trackDir, uuid.New().String())
	for {
		_, err = os.Stat(fpath)
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)
		fpath = filepath.Join(n.trackDir, uuid.New().String())
	}
	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "[os.Create]")
	}
	defer os.Remove(fpath)

	_, err = f.Write(data)
	if err != nil {
		f.Close()
		return errors.Wrap(err, "[Write]")
	}
	err = f.Sync()
	if err != nil {
		f.Close()
		return errors.Wrap(err, "[Sync]")
	}
	f.Close()
	err = os.Rename(fpath, filepath.Join(n.trackDir, fid))
	return err
}

func (n *Node) ParseTrackFile(filehash string) (TrackerInfo, error) {
	var result TrackerInfo
	n.trackLock.RLock()
	b, err := os.ReadFile(filepath.Join(n.trackDir, filehash))
	if err != nil {
		n.trackLock.RUnlock()
		return result, err
	}
	n.trackLock.RUnlock()

	err = json.Unmarshal(b, &result)
	if err != nil {
		var resultold RecordInfo
		err = json.Unmarshal(b, &resultold)
		if err != nil {
			return result, err
		}
		result.Segment = resultold.Segment
		result.Owner = resultold.Owner
		result.Fid = resultold.Fid
		result.FileName = resultold.FileName
		result.BucketName = resultold.BucketName
		result.TerritoryName = resultold.TerritoryName
		result.CacheDir = resultold.CacheDir
		result.Cipher = resultold.Cipher
		result.FileSize = resultold.FileSize
		result.PutFlag = resultold.PutFlag
		return result, nil
	}
	return result, err
}

func (n *Node) HasTrackFile(filehash string) bool {
	n.trackLock.RLock()
	defer n.trackLock.RUnlock()
	_, err := os.Stat(filepath.Join(n.trackDir, filehash))
	return err == nil
}

func (n *Node) ListTrackFiles() ([]string, error) {
	n.trackLock.RLock()
	result, err := filepath.Glob(filepath.Join(n.trackDir, "*"))
	if err != nil {
		n.trackLock.RUnlock()
		return nil, err
	}
	n.trackLock.RUnlock()
	return result, nil
}

func (n *Node) DeleteTrackFile(filehash string) {
	n.trackLock.Lock()
	defer n.trackLock.Unlock()
	os.Remove(filepath.Join(n.trackDir, filehash))
}

func (n *Node) RebuildDirs() {
	os.RemoveAll(n.tmpDir)
	os.RemoveAll(n.dbDir)
	os.RemoveAll(n.logDir)
	os.RemoveAll(n.trackDir)
	os.MkdirAll(n.tmpDir, 0755)
	os.MkdirAll(n.dbDir, 0755)
	os.MkdirAll(n.logDir, 0755)
	os.MkdirAll(n.trackDir, 0755)
}
