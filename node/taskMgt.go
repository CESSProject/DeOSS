/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"time"

	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/p2p-go/out"
	"github.com/mr-tron/base58"
)

func (n *Node) TaskMgt() {
	var (
		ch_trackFile = make(chan bool, 1)
		ch_sdkMgt    = make(chan bool, 1)
	)

	go n.refreshMiner()
	go n.tracker(ch_trackFile)
	go n.sdkMgt(ch_sdkMgt)

	task_10S := time.NewTicker(time.Duration(time.Second * 10))
	defer task_10S.Stop()
	count := 0
	for {
		select {
		case <-task_10S.C:
			err := n.connectChain()
			if err != nil {
				n.Log("err", chain.ERR_RPC_CONNECTION.Error())
				out.Err(chain.ERR_RPC_CONNECTION.Error())
			}
			count++
			if count >= 4320 { //blacklist released every 12 hours
				count = 0
				n.ClearBlackList()
			}

		case <-ch_trackFile:
			go n.tracker(ch_trackFile)

		case <-ch_sdkMgt:
			go n.sdkMgt(ch_sdkMgt)
		}
	}
}

func (n *Node) connectChain() error {
	var err error
	if !n.GetRpcState() {
		n.Log("err", fmt.Sprintf("[%s] %v", n.GetCurrentRpcAddr(), chain.ERR_RPC_CONNECTION))
		out.Err(fmt.Sprintf("[%s] %v", n.GetCurrentRpcAddr(), chain.ERR_RPC_CONNECTION))
		err = n.ReconnectRpc()
		if err != nil {
			return err
		}
		out.Tip(fmt.Sprintf("[%s] rpc reconnection successful", n.GetCurrentRpcAddr()))
		n.Log("info", fmt.Sprintf("[%s] rpc reconnection successful", n.GetCurrentRpcAddr()))
		n.SetRpcState(true)
	}
	return nil
}

func (n *Node) refreshMiner() {
	sminerList, err := n.QueryAllMiner(-1)
	if err == nil {
		for i := 0; i < len(sminerList); i++ {
			minerinfo, err := n.QueryMinerItems(sminerList[i][:], -1)
			if err != nil {
				continue
			}
			if minerinfo.IdleSpace.Uint64() >= sconfig.FragmentSize {
				n.SaveStoragePeer(base58.Encode([]byte(string(minerinfo.PeerId[:]))))
			} else {
				n.DeleteStoragePeer(base58.Encode([]byte(string(minerinfo.PeerId[:]))))
			}
		}
	}
}
