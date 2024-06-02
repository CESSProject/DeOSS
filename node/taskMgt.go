/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"math"
	"math/big"
	"time"

	schain "github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/p2p-go/out"
	"github.com/mr-tron/base58"
)

func (n *Node) TaskMgt() {
	var (
		err             error
		ch_trackFile    = make(chan bool, 1)
		ch_sdkMgt       = make(chan bool, 1)
		ch_refreshMiner = make(chan bool, 1)
	)

	go n.refreshMiner(ch_refreshMiner)
	go n.tracker(ch_trackFile)
	go n.sdkMgt(ch_sdkMgt)

	task_block := time.NewTicker(time.Duration(time.Second * 6))
	defer task_block.Stop()

	task_Minute := time.NewTicker(time.Duration(time.Second * 57))
	defer task_Minute.Stop()
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
			err := n.refreshSelf()
			if err != nil {
				n.Log("err", err.Error())
			}

		case <-ch_trackFile:
			go n.tracker(ch_trackFile)

		default:
			if time.Now().Hour()%5 == 0 {
				if len(ch_refreshMiner) > 0 {
					<-ch_refreshMiner
					go n.refreshMiner(ch_refreshMiner)
				}
			}
		}
	}
}

func (n *Node) connectChain() error {
	var err error
	if !n.GetRpcState() {
		n.Log("err", fmt.Sprintf("[%s] %v", n.GetCurrentRpcAddr(), schain.ERR_RPC_CONNECTION))
		out.Err(fmt.Sprintf("[%s] %v", n.GetCurrentRpcAddr(), schain.ERR_RPC_CONNECTION))
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

func (n *Node) refreshMiner(ch chan<- bool) {
	defer func() { ch <- true }()
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

func (n *Node) refreshSelf() error {
	accInfo, err := n.QueryAccountInfoByAccountID(n.GetSignatureAccPulickey(), -1)
	if err != nil {
		return err
	}
	if len(accInfo.Data.Free.Bytes()) <= 0 {
		n.SetBalances(0)
	} else {
		free_bi, _ := new(big.Int).SetString(accInfo.Data.Free.String(), 10)
		minBanlance_bi, _ := new(big.Int).SetString(schain.MinTransactionBalance, 10)
		free_bi = free_bi.Div(free_bi, minBanlance_bi)
		if free_bi.IsUint64() {
			n.SetBalances(free_bi.Uint64())
		} else {
			n.SetBalances(math.MaxUint64)
		}
	}
	return nil
}
