/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"errors"
	"math"
	"path/filepath"
	"strconv"
	"time"

	schain "github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/CESSProject/p2p-go/out"
	"github.com/mr-tron/base58"
)

func (n *Node) TaskMgt() {
	var (
		err                 error
		ch_trackFile        = make(chan bool, 1)
		ch_refreshMiner     = make(chan bool, 1)
		ch_refreshBlacklist = make(chan bool, 1)
	)

	err = n.LoadPeer(filepath.Join(n.GetRootDir(), "peer_record"))
	if err != nil {
		n.Log("err", "LoadPeer"+err.Error())
	}
	err = n.LoadAccountPeer(filepath.Join(n.GetRootDir(), "account_record"))
	if err != nil {
		n.Log("err", "LoadAccountPeer"+err.Error())
	}
	err = n.LoadBlacklist(filepath.Join(n.GetRootDir(), "blacklist_record"))
	if err != nil {
		n.Log("err", "LoadBlacklist"+err.Error())
	}
	err = n.LoadWhitelist(filepath.Join(n.GetRootDir(), "whitelist_record"))
	if err != nil {
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

	//count := 0
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

			// count++
			// if count >= 4320 { //blacklist released every 12 hours
			// 	count = 0
			// 	n.ClearBlackList()
			// }

		case <-task_Minute.C:
			// if len(ch_trackFile) > 0 {
			// 	<-ch_trackFile
			// 	go n.Tracker(ch_trackFile)
			// }

			err := n.RefreshSelf()
			if err != nil {
				n.Log("err", err.Error())
			}

		case <-task_10Minute.C:
			go n.BackupPeer(filepath.Join(n.GetRootDir(), "peer_record"))
			go n.BackupAccountPeer(filepath.Join(n.GetRootDir(), "account_record"))
			go n.BackupBlacklist(filepath.Join(n.GetRootDir(), "blacklist_record"))
			go n.BackupWhitelist(filepath.Join(n.GetRootDir(), "whitelist_record"))

			if len(ch_refreshBlacklist) > 0 {
				<-ch_refreshBlacklist
				n.RefreshBlacklist(ch_refreshBlacklist)
			}

			n.Log("info", "backup peer")
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
	allpeers := n.GetBlacklist()
	for _, v := range allpeers {
		if n.ConnectPeer(v.Addrs) {
			n.RemoveFromBlacklist(v.Addrs.ID.String())
			n.AddToWhitelist(v.Addrs.ID.String(), "")
		}
	}
}

func (n *Node) RefreshMiner(ch chan<- bool) {
	defer func() { ch <- true }()
	peerid := ""
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
					n.DeletePeerByAccount(acc)
				}
				continue
			}
			peerid = base58.Encode([]byte(string(minerinfo.PeerId[:])))
			n.SavePeerAccount(acc, peerid, string(minerinfo.State), minerinfo.IdleSpace.Uint64())
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
