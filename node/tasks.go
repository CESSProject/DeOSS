/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"math"
	"path/filepath"
	"strconv"
	"time"

	schain "github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-tools/scheduler"
	"github.com/CESSProject/p2p-go/out"
	"github.com/mr-tron/base58"
)

func (n *Node) TaskMgt() {
	var (
		err             error
		ch_trackFile    = make(chan bool, 1)
		ch_refreshMiner = make(chan bool, 1)
	)

	ch_trackFile <- true

	task_block := time.NewTicker(time.Duration(time.Second * 27))
	defer task_block.Stop()

	task_Minute := time.NewTicker(time.Duration(time.Second * 59))
	defer task_Minute.Stop()

	task_Hour := time.NewTicker(time.Duration(time.Second * 3599))
	defer task_Hour.Stop()

	go n.RefreshMiner(ch_refreshMiner)

	count := 0
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
				}
			}
			count++
			if count >= 4320 { //blacklist released every 12 hours
				count = 0
				n.ClearBlackList()
			}

		case <-task_Minute.C:
			if len(ch_trackFile) > 0 {
				<-ch_trackFile
				go n.Tracker(ch_trackFile)
			}

			err := n.RefreshSelf()
			if err != nil {
				n.Log("err", err.Error())
			}

		case <-task_Hour.C:
			if len(ch_refreshMiner) > 0 {
				<-ch_refreshMiner
				go n.RefreshMiner(ch_refreshMiner)
			}

			go n.BackupPeer(filepath.Join(n.Workspace(), "peer_record"))
		}
	}
}

func (n *Node) RefreshMiner(ch chan<- bool) {
	defer func() { ch <- true }()
	sminerList, err := n.QueryAllMiner(-1)
	if err == nil {
		for i := 0; i < len(sminerList); i++ {
			minerinfo, err := n.QueryMinerItems(sminerList[i][:], -1)
			if err != nil {
				continue
			}
			if minerinfo.IdleSpace.Uint64() >= sconfig.FragmentSize {
				peerid := base58.Encode([]byte(string(minerinfo.PeerId[:])))
				n.SavePeerAccount(n.GetSignatureAcc(), peerid)
				addrinfo, ok := n.GetPeer(peerid)
				if ok {
					n.FlushPeerNodes(scheduler.DEFAULT_TIMEOUT, addrinfo)
				}
			}
		}
	}
}

func (n *Node) RefreshSelf() error {
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
