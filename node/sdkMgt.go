/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"time"

	"github.com/AstaFrode/go-libp2p/core/peer"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/p2p-go/core"
	"github.com/mr-tron/base58/base58"

	"github.com/CESSProject/cess-go-sdk/core/pattern"
	ma "github.com/multiformats/go-multiaddr"
)

func (n *Node) sdkMgt(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Log("info", ">>>>> Start sdkMgt task")

	var err error

	var maAddr ma.Multiaddr
	var addrInfo *peer.AddrInfo
	var bootstrap []string

	tick_60s := time.NewTicker(time.Minute)
	defer tick_60s.Stop()

	boots := n.GetBootNodes()
	for _, b := range boots {
		temp, err := core.ParseMultiaddrs(b)
		if err != nil {
			n.Log("err", fmt.Sprintf("[ParseMultiaddrs %v] %v", b, err))
			continue
		}
		bootstrap = append(bootstrap, temp...)
	}
	n.Log("info", fmt.Sprintf("bootnode list:  %s", bootstrap))

	for {
		select {
		case <-tick_60s.C:
			for _, v := range bootstrap {
				maAddr, err = ma.NewMultiaddr(v)
				if err != nil {
					continue
				}
				addrInfo, err = peer.AddrInfoFromP2pAddr(maAddr)
				if err != nil {
					continue
				}
				err = n.Connect(n.GetCtxQueryFromCtxCancel(), *addrInfo)
				if err != nil {
					continue
				}
				n.SavePeer(addrInfo.ID.Pretty(), *addrInfo)
			}
			sminerList, err := n.QuerySminerList()
			if err != nil {
				continue
			}
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
	}
}
