/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	"github.com/CESSProject/cess-go-sdk/core/sdk"
	"github.com/bytedance/sonic"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
)

type Oss interface {
	Run()
}

type Node struct {
	confile.Confile
	logger.Logger
	db.Cache
	sdk.SDK
	*gin.Engine
	signkey   []byte
	trackLock *sync.RWMutex
	lock      *sync.RWMutex
	peers     map[string]peer.AddrInfo
	TrackDir  string
}

// New is used to build a node instance
func New() *Node {
	return &Node{
		trackLock: new(sync.RWMutex),
		lock:      new(sync.RWMutex),
		peers:     make(map[string]peer.AddrInfo, 20),
	}
}

func (n *Node) Run() {
	gin.SetMode(gin.ReleaseMode)
	n.Engine = gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AddAllowHeaders(
		configs.Header_Auth,
		configs.Header_Account,
		configs.Header_BucketName,
		"*",
	)
	n.Engine.MaxMultipartMemory = MaxMemUsed
	n.Engine.Use(cors.New(config))
	// Add route
	n.addRoute()
	// Task management
	go n.TaskMgt()
	log.Println("Listening on port:", n.GetHttpPort())
	// Run
	err := n.Engine.Run(fmt.Sprintf(":%d", n.GetHttpPort()))
	if err != nil {
		log.Fatalf("err: %v", err)
	}
}

func (n *Node) SavePeer(peerid string, addr peer.AddrInfo) {
	if n.lock.TryLock() {
		n.peers[peerid] = addr
		n.lock.Unlock()
	}
}

func (n *Node) HasPeer(peerid string) bool {
	n.lock.RLock()
	defer n.lock.RUnlock()
	_, ok := n.peers[peerid]
	return ok
}

func (n *Node) GetPeer(peerid string) (peer.AddrInfo, bool) {
	n.lock.RLock()
	result, ok := n.peers[peerid]
	n.lock.RUnlock()
	return result, ok
}

func (n *Node) SetSignkey(signkey []byte) {
	n.signkey = signkey
}

func (n *Node) WriteTrackFile(filehash string, data []byte) error {
	if len(data) < MinRecordInfoLength {
		return errors.New("invalid data")
	}
	if len(filehash) != len(pattern.FileHash{}) {
		return errors.New("invalid filehash")
	}
	fpath := filepath.Join(n.TrackDir, uuid.New().String())
	n.trackLock.Lock()
	defer n.trackLock.Unlock()
	os.RemoveAll(fpath)
	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrapf(err, "[os.Create]")
	}
	defer os.Remove(fpath)

	_, err = f.Write(data)
	if err != nil {
		f.Close()
		return errors.Wrapf(err, "[f.Write]")
	}
	err = f.Sync()
	if err != nil {
		f.Close()
		return errors.Wrapf(err, "[f.Sync]")
	}
	f.Close()
	err = os.Rename(fpath, filepath.Join(n.TrackDir, filehash))
	return err
}

func (n *Node) ParseTrackFromFile(filehash string) (RecordInfo, error) {
	var result RecordInfo
	n.trackLock.RLock()
	defer n.trackLock.RUnlock()
	b, err := os.ReadFile(filepath.Join(n.TrackDir, filehash))
	if err != nil {
		return result, err
	}
	err = sonic.Unmarshal(b, &result)
	return result, err
}

func (n *Node) HasTrackFile(filehash string) bool {
	n.trackLock.RLock()
	defer n.trackLock.RUnlock()
	_, err := os.Stat(filepath.Join(n.TrackDir, filehash))
	return err == nil
}

func (n *Node) ListTrackFiles() ([]string, error) {
	n.trackLock.RLock()
	defer n.trackLock.RUnlock()
	return filepath.Glob(fmt.Sprintf("%s/*", n.TrackDir))
}

func (n *Node) DeleteTrackFile(filehash string) {
	n.trackLock.Lock()
	defer n.trackLock.Unlock()
	os.Remove(filepath.Join(n.TrackDir, filehash))
}

func (n *Node) RebuildDirs() {
	os.RemoveAll(n.GetDirs().FileDir)
	os.RemoveAll(n.GetDirs().IdleDataDir)
	os.RemoveAll(n.GetDirs().IdleTagDir)
	os.RemoveAll(n.GetDirs().ProofDir)
	os.RemoveAll(n.GetDirs().ServiceTagDir)
	os.RemoveAll(n.GetDirs().TmpDir)
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Db))
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Log))
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Track))
	os.MkdirAll(n.GetDirs().FileDir, pattern.DirMode)
	os.MkdirAll(n.GetDirs().TmpDir, pattern.DirMode)
}
