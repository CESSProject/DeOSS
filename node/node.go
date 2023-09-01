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
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	"github.com/CESSProject/cess-go-sdk/core/sdk"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/CESSProject/p2p-go/out"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
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
	signkey            []byte
	processingFiles    []string
	processingFileLock *sync.RWMutex
	trackLock          *sync.RWMutex
	lock               *sync.RWMutex
	blacklistLock      *sync.RWMutex
	peers              map[string]peer.AddrInfo
	blacklist          map[string]int64
	trackDir           string
	fadebackDir        string
	peersPath          string
}

// New is used to build a node instance
func New() *Node {
	return &Node{
		processingFileLock: new(sync.RWMutex),
		trackLock:          new(sync.RWMutex),
		lock:               new(sync.RWMutex),
		blacklistLock:      new(sync.RWMutex),
		processingFiles:    make([]string, 0),
		peers:              make(map[string]peer.AddrInfo, 0),
		blacklist:          make(map[string]int64, 0),
	}
}

func (n *Node) Run() {
	gin.SetMode(gin.ReleaseMode)
	n.peersPath = filepath.Join(n.Workspace(), "peers")
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
	out.Tip(fmt.Sprintf("Listening on port: %d", n.GetHttpPort()))
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

func (n *Node) SaveOrUpdatePeerUnSafe(peerid string, addr peer.AddrInfo) {
	n.peers[peerid] = addr
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

func (n *Node) GetAllPeerId() []string {
	n.lock.RLock()
	defer n.lock.RUnlock()
	var result = make([]string, len(n.peers))
	var i int
	for k, _ := range n.peers {
		result[i] = k
		i++
	}
	return result
}

func (n *Node) SavePeersToDisk(path string) error {
	n.lock.RLock()
	buf, err := json.Marshal(n.peers)
	if err != nil {
		n.lock.RUnlock()
		return err
	}
	n.lock.RUnlock()
	err = sutils.WriteBufToFile(buf, path)
	return err
}

func (n *Node) RemovePeerIntranetAddr() {
	n.lock.Lock()
	defer n.lock.Unlock()
	for k, v := range n.peers {
		var addrInfo peer.AddrInfo
		var addrs []multiaddr.Multiaddr
		for _, addr := range v.Addrs {
			if ipv4, ok := utils.FildIpv4([]byte(addr.String())); ok {
				if ok, err := utils.IsIntranetIpv4(ipv4); err == nil {
					if !ok {
						addrs = append(addrs, addr)
					}
				}
			}
		}
		if len(addrs) > 0 {
			addrInfo.ID = v.ID
			addrInfo.Addrs = utils.RemoveRepeatedAddr(addrs)
			n.SaveOrUpdatePeerUnSafe(v.ID.Pretty(), addrInfo)
		} else {
			delete(n.peers, k)
		}
	}
}

func (n *Node) LoadPeersFromDisk(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	n.lock.Lock()
	err = json.Unmarshal(buf, &n.peers)
	n.lock.Unlock()
	return err
}

func (n *Node) EncodePeers() []byte {
	n.lock.Lock()
	buf, _ := json.Marshal(&n.peers)
	n.lock.Unlock()
	return buf
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

func (n *Node) WriteTrackFile(filehash string, data []byte) error {
	if len(data) < MinRecordInfoLength {
		return errors.New("invalid data")
	}
	if len(filehash) != len(pattern.FileHash{}) {
		return errors.New("invalid filehash")
	}
	fpath := filepath.Join(n.trackDir, uuid.New().String())
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
	err = os.Rename(fpath, filepath.Join(n.trackDir, filehash))
	return err
}

func (n *Node) ParseTrackFromFile(filehash string) (RecordInfo, error) {
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
	result, err := filepath.Glob(fmt.Sprintf("%s/*", n.trackDir))
	if err != nil {
		n.trackLock.RUnlock()
		return nil, err
	}
	n.trackLock.RUnlock()

	var linuxFileAttr *syscall.Stat_t
	var keys = make([]int, 0)
	var resultMap = make(map[int64]string, 0)
	for _, v := range result {
		fs, err := os.Stat(v)
		if err == nil {
			linuxFileAttr = fs.Sys().(*syscall.Stat_t)
			resultMap[linuxFileAttr.Ctim.Sec] = v
			keys = append(keys, int(linuxFileAttr.Ctim.Sec))
		}
	}
	sort.Ints(keys)
	var resultFile = make([]string, len(keys))
	for k, v := range keys {
		resultFile[k] = resultMap[int64(v)]
	}
	return resultFile, nil
}

func (n *Node) DeleteTrackFile(filehash string) {
	n.trackLock.Lock()
	defer n.trackLock.Unlock()
	os.Remove(filepath.Join(n.trackDir, filehash))
}

func (n *Node) HasBlacklist(peerid string) (int64, bool) {
	n.blacklistLock.RLock()
	t, ok := n.blacklist[peerid]
	n.blacklistLock.RUnlock()
	return t, ok
}

func (n *Node) AddToBlacklist(peerid string) {
	n.blacklistLock.Lock()
	if _, ok := n.blacklist[peerid]; !ok {
		n.blacklist[peerid] = time.Now().Unix()
	}
	n.blacklistLock.Unlock()
}

func (n *Node) DelFromBlacklist(peerid string) {
	n.blacklistLock.Lock()
	delete(n.blacklist, peerid)
	n.blacklistLock.Unlock()
}

func (n *Node) RebuildDirs() {
	os.RemoveAll(n.GetDirs().FileDir)
	os.RemoveAll(n.GetDirs().ServiceTagDir)
	os.RemoveAll(n.GetDirs().TmpDir)
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Db))
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Log))
	os.RemoveAll(filepath.Join(n.Workspace(), configs.Track))
	os.MkdirAll(n.GetDirs().FileDir, pattern.DirMode)
	os.MkdirAll(n.GetDirs().TmpDir, pattern.DirMode)
	os.MkdirAll(filepath.Join(n.Workspace(), configs.Track), pattern.DirMode)
}
