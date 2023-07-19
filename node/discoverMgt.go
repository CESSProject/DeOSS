/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"reflect"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/time/rate"
)

func (n *Node) discoverMgt(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Discover("info", ">>>>> start discoverMgt <<<<<")
	tickDiscover := time.NewTicker(time.Minute * 10)
	defer tickDiscover.Stop()

	var r1 = rate.Every(time.Second * 5)
	var limit = rate.NewLimiter(r1, 1)

	var r2 = rate.Every(time.Minute * 30)
	var printLimit = rate.NewLimiter(r2, 1)

	err := n.LoadPeersFromDisk(n.peersPath)
	if err != nil {
		n.Discover("err", err.Error())
	}

	n.RouteTableFindPeers(0)

	for {
		select {
		case discoveredPeer, _ := <-n.GetDiscoveredPeers():
			if limit.Allow() {
				n.Discover("info", "reset")
				tickDiscover.Reset(time.Minute * 10)
			}
			if len(discoveredPeer.Responses) == 0 {
				break
			}
			for _, v := range discoveredPeer.Responses {
				//n.SavePeer(v.ID.Pretty(), *v)
				var addrInfo peer.AddrInfo
				var addrs []multiaddr.Multiaddr
				for _, addr := range v.Addrs {
					if !reflect.ValueOf(addr).IsNil() {
						if ipv4, ok := utils.FildIpv4(addr.Bytes()); ok {
							if ok, err := utils.IsIntranetIpv4(ipv4); err == nil {
								if !ok {
									addrs = append(addrs, addr)
								}
							}
						}
					}
				}
				if len(addrs) > 0 {
					addrInfo.ID = v.ID
					addrInfo.Addrs = addrs
					n.SavePeer(v.ID.Pretty(), addrInfo)
				}
			}
		case <-tickDiscover.C:
			if printLimit.Allow() {
				allpeer := n.GetAllPeerId()
				for _, v := range allpeer {
					n.Discover("info", fmt.Sprintf("found %s", v))
				}
				err = n.SavePeersToDisk(n.peersPath)
				if err != nil {
					n.Discover("err", err.Error())
				}
			}
			n.Discover("info", "RouteTableFindPeers")
			_, err := n.RouteTableFindPeers(len(n.peers) + 20)
			if err != nil {
				n.Discover("err", err.Error())
			}
		}
	}
}
