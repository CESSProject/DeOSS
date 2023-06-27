/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	ma "github.com/multiformats/go-multiaddr"
)

func (n *Node) discoverMgt(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Discover("info", ">>>>> Start discoverMgt task")

	var err error
	var peerid string
	var addr string
	var multiaddr string
	var boot []string
	var bootnodes []string
	var addrInfo *peer.AddrInfo

	tick_BlockInterval := time.NewTicker(pattern.BlockInterval * 30)
	defer tick_BlockInterval.Stop()

	tick_60s := time.NewTicker(time.Minute)
	defer tick_60s.Stop()

	for {
		select {
		case <-tick_BlockInterval.C:
			if !n.GetChainState() {
				n.Discover("err", pattern.ERR_RPC_CONNECTION.Error())
				err = n.Reconnect()
				if err != nil {
					log.Println(pattern.ERR_RPC_CONNECTION)
					n.Discover("err", pattern.ERR_RPC_CONNECTION.Error())
				} else {
					log.Println("rpc reconnection successful")
					n.Discover("info", "rpc reconnection successfully")
				}
			}
		case <-tick_60s.C:
			boot = n.GetBootNodes()
			for _, v := range boot {
				bootnodes, err = utils.ParseMultiaddrs(v)
				if err != nil {
					continue
				}
				for _, v := range bootnodes {
					addr, err := ma.NewMultiaddr(v)
					if err != nil {
						continue
					}
					addrInfo, err = peer.AddrInfoFromP2pAddr(addr)
					if err != nil {
						continue
					}
					err = n.Connect(n.GetRootCtx(), *addrInfo)
					if err != nil {
						n.Log("err", err.Error())
						continue
					}
					n.SavePeer(addrInfo.ID.Pretty())
				}
			}
			if !n.GetDiscoverSt() {
				n.StartDiscover()
			}
		case discoverPeer := <-n.DiscoveredPeer():
			peerid = discoverPeer.ID.Pretty()
			n.Discover("info", fmt.Sprintf("Found a peer: %s", peerid))
			err := n.Connect(n.GetRootCtx(), discoverPeer)
			if err != nil {
				n.Discover("err", fmt.Sprintf("Connectto %s failed: %v", peerid, err))
				continue
			}
			n.Discover("info", fmt.Sprintf("Connect to %s ", peerid))
			n.SavePeer(peerid)

			for _, v := range discoverPeer.Addrs {
				addr = v.String()
				temp := strings.Split(addr, "/")
				for _, vv := range temp {
					if sutils.IsIPv4(vv) {
						if vv[len(vv)-1] == byte(49) && vv[len(vv)-3] == byte(48) {
							continue
						}
						multiaddr = fmt.Sprintf("%s/p2p/%s", addr, peerid)
						n.AddMultiaddrToPeerstore(multiaddr, time.Hour)
					}
				}
			}
		}
		time.Sleep(time.Millisecond * 10)
	}
}
