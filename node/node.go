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
	"sync/atomic"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/inter"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/CESSProject/cess-go-tools/cacher"
	"github.com/CESSProject/cess-go-tools/scheduler"
	"github.com/CESSProject/p2p-go/core"
	"github.com/CESSProject/p2p-go/out"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Node struct {
	signkey            []byte
	processingFiles    []string
	processingFileLock *sync.RWMutex
	trackLock          *sync.RWMutex
	lock               *sync.RWMutex
	blacklistLock      *sync.RWMutex
	storagePeersLock   *sync.RWMutex
	findPeer           *atomic.Uint32
	storagePeers       map[string]struct{}
	blacklist          map[string]int64
	trackDir           string
	fadebackDir        string
	inter.TrackFile
	confile.Confile
	logger.Logger
	db.Cache
	PeerRecord
	cacher.FileCache
	scheduler.Selector
	*chain.ChainClient
	*core.PeerNode
	*gin.Engine
}

// New is used to build a node instance
func New() *Node {
	return &Node{
		processingFileLock: new(sync.RWMutex),
		trackLock:          new(sync.RWMutex),
		lock:               new(sync.RWMutex),
		blacklistLock:      new(sync.RWMutex),
		storagePeersLock:   new(sync.RWMutex),
		PeerRecord:         NewPeerRecord(),
		TrackFile:          inter.NewTeeRecord(),
		processingFiles:    make([]string, 0),
		storagePeers:       make(map[string]struct{}, 0),
		blacklist:          make(map[string]int64, 0),
		findPeer:           new(atomic.Uint32),
	}
}

func (n *Node) Run() {
	gin.SetMode(gin.ReleaseMode)
	n.Engine = gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AddAllowHeaders("*")
	n.Engine.MaxMultipartMemory = MaxMemUsed
	n.Engine.Use(cors.New(config))
	n.Engine.GET("/version", n.Get_version)
	n.Engine.GET("/bucket", n.Get_bucket)
	n.Engine.GET(fmt.Sprintf("/metadata/:%s", HTTP_ParameterName_Fid), n.Get_metadata)
	n.Engine.GET(fmt.Sprintf("/download/:%s", HTTP_ParameterName_Fid), n.Download_file)
	n.Engine.GET(fmt.Sprintf("/canfiles/:%s", HTTP_ParameterName_Fid), n.GetCanFileHandle)
	n.Engine.GET(fmt.Sprintf("/open/:%s", HTTP_ParameterName_Fid), n.Preview_file)

	n.Engine.PUT("/bucket", n.Put_bucket)
	n.Engine.PUT("/file", n.Put_file)
	n.Engine.PUT("/object", n.Put_object)
	n.Engine.PUT("/chunks", n.PutChunksHandle)

	n.Engine.DELETE(fmt.Sprintf("/file/:%s", HTTP_ParameterName), n.Delete_file)
	n.Engine.DELETE(fmt.Sprintf("/bucket/:%s", HTTP_ParameterName), n.Delete_bucket)

	n.Engine.GET("/404", n.NotFound)
	out.Tip(fmt.Sprintf("Listening on port: %d", n.GetHttpPort()))

	// tasks
	go n.TaskMgt()

	err := n.Engine.Run(fmt.Sprintf(":%d", n.GetHttpPort()))
	if err != nil {
		log.Fatalf("err: %v", err)
	}
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

func (n *Node) SaveStoragePeer(peerid string) {
	n.storagePeersLock.Lock()
	n.storagePeers[peerid] = struct{}{}
	n.storagePeersLock.Unlock()
}

func (n *Node) DeleteStoragePeer(peerid string) {
	n.storagePeersLock.Lock()
	delete(n.storagePeers, peerid)
	n.storagePeersLock.Unlock()
}

func (n *Node) HasStoragePeer(peerid string) bool {
	n.storagePeersLock.RLock()
	defer n.storagePeersLock.RUnlock()
	_, ok := n.storagePeers[peerid]
	return ok
}

func (n *Node) GetAllStoragePeerId() []string {
	n.storagePeersLock.RLock()
	defer n.storagePeersLock.RUnlock()
	var result = make([]string, len(n.storagePeers))
	var i int
	for k := range n.storagePeers {
		result[i] = k
		i++
	}
	return result
}

func (n *Node) SetSignkey(signkey []byte) {
	n.signkey = signkey
}

func (n *Node) SetTrackDir(dir string) {
	n.trackDir = dir
}

func (n *Node) SetFadebackDir(dir string) {
	n.fadebackDir = dir
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

func (n *Node) ParseTrackFile(filehash string) (RecordInfo, error) {
	var result RecordInfo
	n.trackLock.RLock()
	defer n.trackLock.RUnlock()
	b, err := os.ReadFile(filepath.Join(n.trackDir, filehash))
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(b, &result)
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
	os.RemoveAll(n.GetDirs().TmpDir)
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Db))
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Log))
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Track))
	os.MkdirAll(n.GetDirs().FileDir, 0755)
	os.MkdirAll(n.GetDirs().TmpDir, 0755)
	os.MkdirAll(filepath.Join(n.Workspace(), configs.Track), 0755)
}
