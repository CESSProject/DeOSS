/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/libp2p/go-libp2p/core/peer"
	peerstore "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/time/rate"
)

func (n *Node) findPeers(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Discover("info", ">>>>> start findPeers <<<<<")

	var ok bool
	var foundPeer peer.AddrInfo
	var tick = time.NewTicker(time.Minute)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			peerChan, err := n.GetRoutingTable().FindPeers(n.GetCtxQueryFromCtxCancel(), n.GetRendezvousVersion())
			if err != nil {
				continue
			}
			ok = true
			for ok {
				select {
				case foundPeer, ok = <-peerChan:
					if !ok {
						break
					}
					if foundPeer.ID == n.ID() {
						continue
					}
					err := n.Connect(n.GetCtxQueryFromCtxCancel(), foundPeer)
					if err != nil {
						//fmt.Println("xx Failed connecting to ", foundPeer.ID.Pretty(), ", err:", err)
						n.Peerstore().RemovePeer(foundPeer.ID)
					} else {
						for _, addr := range foundPeer.Addrs {
							n.Peerstore().AddAddr(foundPeer.ID, addr, peerstore.AddressTTL)
						}
						//fmt.Println("++ Connected to:", foundPeer.ID.Pretty())
					}
				}
			}
		}
	}
}

func (n *Node) recvPeers(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Discover("info", ">>>>> start recvPeers <<<<<")

	for {
		select {
		case foundPeer := <-n.GetDiscoveredPeers():
			for _, v := range foundPeer.Responses {
				if v != nil {
					if len(v.Addrs) > 0 {
						n.Peerstore().AddAddrs(v.ID, v.Addrs, peerstore.AddressTTL)
					}
				}
			}
		}
	}
}

func (n *Node) discoverMgt2(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Discover("info", ">>>>> start discoverMgt <<<<<")

	go func() {
		for {
			select {
			case foundPeer := <-n.GetDiscoveredPeers():
				for _, v := range foundPeer.Responses {
					//fmt.Println("***************************Fount id:", v.ID.String(), "addr: ", v.Addrs)
					n.Peerstore().AddAddrs(v.ID, v.Addrs, peerstore.AddressTTL)
				}
			}
		}
	}()

	tickDiscover := time.NewTicker(time.Second * 10)
	defer tickDiscover.Stop()
	for {
		select {
		case <-tickDiscover.C:
			//peerChan := kademliaDHT.FindProvidersAsync(ctx, cid.Cid{}, 1)
			peerChan, err := n.RouteTableFindPeers(0)
			if err != nil {
				fmt.Println("xxx FindPeers err: ", err)
				continue
			}
			var ok = true
			var aPeer peer.AddrInfo
			for ok {
				select {
				case aPeer, ok = <-peerChan:
					if !ok {
						break
					}
					if aPeer.ID.Pretty() == n.GetDht().Host().ID().Pretty() {
						continue
					}
					err := n.Connect(n.GetCtxQueryFromCtxCancel(), aPeer)
					if err != nil {
						fmt.Println("xxx Failed connecting to ", aPeer.ID.Pretty(), ", error:", err)
					} else {
						for _, addr := range aPeer.Addrs {
							n.Peerstore().AddAddr(aPeer.ID, addr, peerstore.PermanentAddrTTL)
						}
						fmt.Println("+++ Connected to:", aPeer.ID.Pretty())
					}
				}
			}
		}
	}
}

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
	} else {
		n.RemovePeerIntranetAddr()
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
				var addrInfo peer.AddrInfo
				var addrs []multiaddr.Multiaddr
				for _, addr := range v.Addrs {
					if !utils.InterfaceIsNIL(addr) {
						if ipv4, ok := utils.FildIpv4([]byte(addr.String())); ok {
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
					addrInfo.Addrs = utils.RemoveRepeatedAddr(addrs)
					n.SavePeer(v.ID.Pretty(), addrInfo)
				}
			}
		case <-tickDiscover.C:
			if printLimit.Allow() {
				allpeer := n.GetAllPeerId()
				for _, v := range allpeer {
					n.Discover("info", fmt.Sprintf("found %s", v))
				}
				n.RemovePeerIntranetAddr()
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
