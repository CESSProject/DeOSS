/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/common/confile"
	out "github.com/CESSProject/DeOSS/common/fout"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/lru"
	"github.com/CESSProject/DeOSS/common/record"
	"github.com/CESSProject/DeOSS/common/tracker"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/common/workspace"
	"github.com/CESSProject/cess-go-sdk/chain"
	schain "github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-ping/ping"
)

type Node struct {
	*confile.Config
	*lru.LRUCache
	*gin.Engine
	chain.Chainer
	workspace.Workspace
	logger.Logger
	record.MinerRecorder
	tracker.Tracker
}

func NewEmptyNode() *Node {
	return &Node{}
}

func NewNodeWithConfig(cfg *confile.Config) *Node {
	return &Node{Config: cfg}
}

func (n *Node) InitChainclient(cli chain.Chainer) {
	n.Chainer = cli
}

func (n *Node) InitWorkspace(ws string) {
	n.Workspace = workspace.NewWorkspace(ws)
}

func (n *Node) InitLogger(lg logger.Logger) {
	n.Logger = lg
}

func (n *Node) InitMinerRecord(r record.MinerRecorder) {
	n.MinerRecorder = r
}

func (n *Node) InitTracker(t tracker.Tracker) {
	n.Tracker = t
}

func (n *Node) InitServer(s *gin.Engine) {
	n.Engine = s
}

func (n *Node) InitLRUCache(lru *lru.LRUCache) {
	n.LRUCache = lru
}

func (n *Node) Start() {
	var (
		err                 error
		ch_trackFile        = make(chan bool, 1)
		ch_refreshMiner     = make(chan bool, 1)
		ch_refreshBlacklist = make(chan bool, 1)
	)

	err = n.LoadMinerlist(filepath.Join(n.GetRootDir(), "miner_record"))
	if err != nil {
		os.Remove(filepath.Join(n.GetRootDir(), "miner_record"))
		n.Log("err", "LoadMinerlist"+err.Error())
	}
	err = n.LoadBlacklist(filepath.Join(n.GetRootDir(), "blacklist_record"))
	if err != nil {
		os.Remove(filepath.Join(n.GetRootDir(), "blacklist_record"))
		n.Log("err", "LoadBlacklist"+err.Error())
	}
	err = n.LoadWhitelist(filepath.Join(n.GetRootDir(), "whitelist_record"))
	if err != nil {
		os.Remove(filepath.Join(n.GetRootDir(), "whitelist_record"))
		n.Log("err", "LoadWhitelist"+err.Error())
	}

	ch_trackFile <- true

	task_block := time.NewTicker(time.Duration(time.Second * 27))
	defer task_block.Stop()

	task_Minute := time.NewTicker(time.Duration(time.Second * 59))
	defer task_Minute.Stop()

	task_10Minute := time.NewTicker(time.Duration(time.Second * 597))
	defer task_10Minute.Stop()

	task_Hour := time.NewTicker(time.Duration(time.Second * 3599))
	defer task_Hour.Stop()

	go n.RefreshMiner(ch_refreshMiner)
	go n.RefreshBlacklist(ch_refreshBlacklist)
	go n.TrackerV2()

	out.Ok("Service started successfully")

	chainState := true
	for {
		select {
		case <-task_block.C:
			chainState = n.GetRpcState()
			if !chainState {
				err = n.ReconnectRpc()
				if err != nil {
					n.Log("err", schain.ERR_RPC_CONNECTION.Error())
					out.Err(schain.ERR_RPC_CONNECTION.Error())
				} else {
					n.Log("info", "rpc reconnect suc: "+n.GetCurrentRpcAddr())
				}
			}

		case <-task_Minute.C:
			err := n.RefreshSelf()
			if err != nil {
				n.Log("err", err.Error())
			}

		case <-task_10Minute.C:
			go n.BackupMinerlist(filepath.Join(n.GetRootDir(), "miner_record"))
			go n.BackupBlacklist(filepath.Join(n.GetRootDir(), "blacklist_record"))
			go n.BackupWhitelist(filepath.Join(n.GetRootDir(), "whitelist_record"))

			if len(ch_refreshBlacklist) > 0 {
				<-ch_refreshBlacklist
				n.RefreshBlacklist(ch_refreshBlacklist)
			}

		case <-task_Hour.C:
			if len(ch_refreshMiner) > 0 {
				<-ch_refreshMiner
				go n.RefreshMiner(ch_refreshMiner)
			}
		}
	}
}

func (n *Node) RefreshBlacklist(ch chan<- bool) {
	defer func() { ch <- true }()
	var err error
	var url string
	blacklist := n.GetAllBlacklist()
	for _, v := range blacklist {
		url = strings.ReplaceAll(v.Addr, "\u0000", "")
		url = strings.TrimSuffix(url, "/")
		if strings.Contains(url, ":") {
			url = strings.TrimPrefix(url, "http://")
			_, err = net.DialTimeout("tcp", url, time.Second*5)
			if err == nil {
				n.RemoveFromBlacklist(v.Account)
			}
		} else {
			_, err = ping.NewPinger(url)
			if err == nil {
				n.RemoveFromBlacklist(v.Account)
			}
		}
	}
}

func (n *Node) RefreshMiner(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()
	sminerList, err := n.QueryAllMiner(-1)
	if err == nil {
		for i := 0; i < len(sminerList); i++ {
			acc, err := sutils.EncodePublicKeyAsCessAccount(sminerList[i][:])
			if err != nil {
				n.Log("err", err.Error())
				continue
			}
			minerinfo, err := n.QueryMinerItems(sminerList[i][:], -1)
			if err != nil {
				if !errors.Is(err, schain.ERR_RPC_EMPTY_VALUE) {
					n.Log("err", err.Error())
				} else {
					n.DeleteMinerinfo(acc)
				}
				continue
			}
			n.SaveMinerinfo(acc, string(minerinfo.Endpoint[:]), string(minerinfo.State), minerinfo.IdleSpace.Uint64())
		}
	}
}

func (n *Node) RefreshSelf() error {
	defer func() {
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()
	accInfo, err := n.QueryAccountInfoByAccountID(n.GetSignatureAccPulickey(), -1)
	if err != nil {
		return err
	}

	free := accInfo.Data.Free.String()
	if len(free) <= len(schain.TokenPrecision_CESS) {
		n.SetBalances(0)
		return nil
	}

	free = free[:len(free)-len(schain.TokenPrecision_CESS)]
	free_uint, err := strconv.ParseUint(free, 10, 64)
	if err != nil {
		n.SetBalances(math.MaxUint64)
		return nil
	}
	n.SetBalances(free_uint)
	return nil
}
