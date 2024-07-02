/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
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
	n.Engine.GET(fmt.Sprintf("/metedata/:%s", HTTP_ParameterName_Fid), n.Get_metadata)
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

func (n *Node) Run_bkp() {
	server, err := buildHttpServer(n)
	if err != nil {
		log.Fatalf("[buildHttpServer] %v", err)
	}
	go func() {
		if err = server.ListenAndServe(); err != nil {
			log.Fatalf("[ListenAndServe] %v", err)
		}
	}()
	out.Tip(fmt.Sprintf("Listening on port: %d", n.GetHttpPort()))

	// tasks
	go n.TaskMgt()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	log.Println("Received an exit signal: ", sig.String())
	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx_timeout, _ := context.WithTimeout(context.Background(), 5*time.Second)
	if err := server.Shutdown(ctx_timeout); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}
	log.Println("Server has exited")
	os.Exit(0)

}

func buildHttpServer(n *Node) (*http.Server, error) {
	gin.SetMode(gin.ReleaseMode)
	ginsrv := gin.Default()
	ginConfig := cors.DefaultConfig()
	ginConfig.AllowAllOrigins = true
	ginConfig.AddAllowHeaders("*")
	ginsrv.Use(cors.New(ginConfig))

	// route
	//ginsrv.POST("/feedback/log", n.FeedbackLog)
	//ginsrv.POST("/restore", n.RestoreFile)
	//ginsrv.GET("/restore", n.GetRestoreHandle)

	ginsrv.GET("/version", n.Get_version)
	ginsrv.GET("/bucket", n.Get_bucket)
	ginsrv.GET(fmt.Sprintf("/metedata/:%s", HTTP_ParameterName_Fid), n.Get_metadata)
	ginsrv.GET(fmt.Sprintf("/download/:%s", HTTP_ParameterName_Fid), n.Download_file)
	ginsrv.GET(fmt.Sprintf("/canfiles/:%s", HTTP_ParameterName_Fid), n.GetCanFileHandle)
	ginsrv.GET(fmt.Sprintf("/open/:%s", HTTP_ParameterName_Fid), n.Preview_file)

	ginsrv.PUT("/bucket", n.Put_bucket)
	ginsrv.PUT("/file", n.Put_file)
	ginsrv.PUT("/object", n.Put_object)
	ginsrv.PUT("/chunks", n.PutChunksHandle)

	ginsrv.DELETE(fmt.Sprintf("/file/:%s", HTTP_ParameterName), n.Delete_file)
	ginsrv.DELETE(fmt.Sprintf("/bucket/:%s", HTTP_ParameterName), n.Delete_bucket)

	ginsrv.GET("/404", n.NotFound)

	// http server
	return &http.Server{
		Addr:           fmt.Sprintf(":%d", n.GetHttpPort()),
		Handler:        ginsrv,
		ReadTimeout:    time.Duration(30) * time.Second,
		WriteTimeout:   time.Duration(30) * time.Second,
		MaxHeaderBytes: 1024 * 1024,
	}, nil
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
