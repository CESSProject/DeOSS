/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/mr-tron/base58/base58"
)

func (n *Node) sdkMgt(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Log("info", ">>>>> Start sdkMgt task")

	tick_60s := time.NewTicker(time.Minute)
	defer tick_60s.Stop()

	for range tick_60s.C {
		sminerList, err := n.QueryAllMiner(-1)
		if err != nil {
			continue
		}
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
