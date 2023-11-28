/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"fmt"
	"time"

	"github.com/AstaFrode/go-libp2p/core/host"
	"github.com/AstaFrode/go-libp2p/core/peer"
	peerstore "github.com/AstaFrode/go-libp2p/core/peerstore"
	drouting "github.com/AstaFrode/go-libp2p/p2p/discovery/routing"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
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

	sminerList, err := n.QuerySminerList()
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

	for {
		select {
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

func discoverPeers(ctx context.Context, h host.Host, routingDiscovery *drouting.RoutingDiscovery, rendverse string) {
	fmt.Println("Searching for peers...")
	// Look for others who have announced and attempt to connect to them
	tick := time.NewTicker(time.Second * 5)
	for {
		select {
		case <-tick.C:
			//peerChan := kademliaDHT.FindProvidersAsync(ctx, cid.Cid{}, 1)
			peerChan, err := routingDiscovery.FindPeers(ctx, rendverse)
			if err != nil {
				fmt.Println("FindPeers err: ", err)
				continue
			}
			var ok = true
			var peer peer.AddrInfo
			for ok {
				select {
				case peer, ok = <-peerChan:
					if !ok {
						break
					} else {
						fmt.Println("++++++++Found peer: ", peer)
					}
					if peer.ID == h.ID() {
						continue // No self connection
					}
					err := h.Connect(ctx, peer)
					if err != nil {
						fmt.Println("++++++++Failed connecting to ", peer.ID.Pretty(), ", error:", err)
					} else {
						for _, addr := range peer.Addrs {
							h.Peerstore().AddAddr(peer.ID, addr, peerstore.PermanentAddrTTL)
						}
						fmt.Println("++++++++Connected to:", peer.ID.Pretty())
					}
				}
				time.Sleep(time.Second)
			}
		}
	}
}
