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

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	peerstore "github.com/libp2p/go-libp2p/core/peerstore"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
)

func (n *Node) TaskMgt() {
	var (
		ch_findPeers = make(chan bool, 1)
		ch_recvPeers = make(chan bool, 1)

		ch_syncBlock = make(chan bool, 1)
		ch_syncFile  = make(chan bool, 1)

		ch_trackFile = make(chan bool, 1)
		ch_sdkMgt    = make(chan bool, 1)

		//ch_notifyBlocks = make(chan bool, 1)
		//ch_getBlock1 = make(chan bool, 1)
		//ch_discoverMgt = make(chan bool, 1)
	)

	go n.findPeers(ch_findPeers)
	go n.recvPeers(ch_recvPeers)

	// go n.getBlocks(ch_getBlock1)
	// go n.noticyBlocks(ch_notifyBlocks)

	go n.syncBlock(ch_syncBlock)
	go n.syncFiles(ch_syncFile)

	go n.tracker(ch_trackFile)
	go n.sdkMgt(ch_sdkMgt)

	// tick_Minute := time.NewTicker(time.Minute)
	// defer tick_Minute.Stop()

	// wantCid1, err := cid.Decode(os.Args[2])
	// if err != nil {
	// 	fmt.Println("decode want cid1 err: ", err)
	// 	os.Exit(1)
	// }

	// wantCid2, err := cid.Decode(os.Args[3])
	// if err != nil {
	// 	fmt.Println("decode want cid2 err: ", err)
	// 	os.Exit(1)
	// }

	//---------------------------------------dht route start-----------------------------------------------
	// go discoverPeers(n.GetCtxQueryFromCtxCancel(), n.GetDht().Host(), n.GetRoutingTable(), n.GetRendezvousVersion())
	// go func() {
	// 	for {
	// 		select {
	// 		case peer := <-n.GetDiscoveredPeers():
	// 			for _, v := range peer.Responses {
	// 				fmt.Println("***************************Fount id:", v.ID.String(), "addr: ", v.Addrs)
	// 				n.Peerstore().AddAddrs(v.ID, v.Addrs, peerstore.AddressTTL)
	// 			}
	// 		}
	// 	}
	// }()
	// time.Sleep(time.Second * 20)
	// go func() {
	// 	for {
	// 		fmt.Println("Will get cid1 ", wantCid1, " ...")
	// 		ctxOut, _ := context.WithTimeout(context.Background(), time.Second*5)
	// 		getBlock, err := n.GetBitSwap().GetBlock(ctxOut, wantCid1)
	// 		if err != nil {
	// 			fmt.Println("Get want cid1 err:", err)
	// 		} else {
	// 			fmt.Println("Get want cid1 suc:", string(getBlock.RawData()))
	// 		}
	// 		time.Sleep(time.Second * 5)
	// 	}
	// }()

	// go func() {
	// 	for {
	// 		fmt.Println("Will get cid2 ", wantCid2, " ...")
	// 		ctxOut, _ := context.WithTimeout(context.Background(), time.Second*5)
	// 		getBlock, err := n.GetBitSwap().GetBlock(ctxOut, wantCid2)
	// 		if err != nil {
	// 			fmt.Println("Get want cid2 err:", err)
	// 		} else {
	// 			fmt.Println("Get want cid2 suc:", string(getBlock.RawData()))
	// 		}
	// 		time.Sleep(time.Second * 5)
	// 	}
	// }()

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

			// case <-ch_notifyBlocks:
			// 	go n.noticyBlocks(ch_notifyBlocks)

			// case <-ch_getBlock1:
			// 	go n.getBlocks(ch_getBlock1)
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
