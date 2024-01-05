/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"time"

	"github.com/CESSProject/cess-go-sdk/core/pattern"
	"github.com/CESSProject/p2p-go/out"
	"github.com/mr-tron/base58"
)

func (n *Node) TaskMgt() {
	var (
		ch_findPeers = make(chan bool, 1)
		ch_recvPeers = make(chan bool, 1)

		ch_syncBlock = make(chan bool, 1)
		ch_syncFile  = make(chan bool, 1)

		ch_trackFile = make(chan bool, 1)
		ch_sdkMgt    = make(chan bool, 1)

		ch_notifyBlocks = make(chan bool, 1)
	)

	sminerList, err := n.QueryAllSminerAccount()
	if err == nil {
		for i := 0; i < len(sminerList); i++ {
			minerinfo, err := n.QueryStorageMiner(sminerList[i][:])
			if err != nil {
				continue
			}
			if minerinfo.IdleSpace.Uint64() >= pattern.FragmentSize {
				n.SaveStoragePeer(base58.Encode([]byte(string(minerinfo.PeerId[:]))))
			} else {
				n.DeleteStoragePeer(base58.Encode([]byte(string(minerinfo.PeerId[:]))))
			}
		}
	}

	go n.findPeers(ch_findPeers)
	go n.recvPeers(ch_recvPeers)

	go n.noticeBlocks(ch_notifyBlocks)
	go n.syncBlock(ch_syncBlock)
	go n.syncFiles(ch_syncFile)

	go n.tracker(ch_trackFile)
	go n.sdkMgt(ch_sdkMgt)

	task_10S := time.NewTicker(time.Duration(time.Second * 10))
	defer task_10S.Stop()

	for {
		select {
		case <-task_10S.C:
			err := n.connectChain()
			if err != nil {
				n.Log("err", pattern.ERR_RPC_CONNECTION.Error())
				out.Err(pattern.ERR_RPC_CONNECTION.Error())
			}

		case <-ch_findPeers:
			go n.findPeers(ch_findPeers)

		case <-ch_recvPeers:
			go n.recvPeers(ch_recvPeers)

		case <-ch_syncBlock:
			go n.syncBlock(ch_syncBlock)

		case <-ch_syncFile:
			go n.syncFiles(ch_syncFile)

		case <-ch_trackFile:
			go n.tracker(ch_trackFile)

		case <-ch_sdkMgt:
			go n.sdkMgt(ch_sdkMgt)

		case <-ch_notifyBlocks:
			go n.noticeBlocks(ch_notifyBlocks)
		}
	}
}

func (n *Node) connectChain() error {
	var err error
	if !n.GetChainState() {
		n.Log("err", fmt.Sprintf("[%s] %v", n.GetCurrentRpcAddr(), pattern.ERR_RPC_CONNECTION))
		out.Err(fmt.Sprintf("[%s] %v", n.GetCurrentRpcAddr(), pattern.ERR_RPC_CONNECTION))
		err = n.ReconnectRPC()
		if err != nil {
			return err
		}
		out.Tip(fmt.Sprintf("[%s] rpc reconnection successful", n.GetCurrentRpcAddr()))
		n.Log("info", fmt.Sprintf("[%s] rpc reconnection successful", n.GetCurrentRpcAddr()))
		n.SetChainState(true)
	}
	return nil
}
