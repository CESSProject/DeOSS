/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"time"

	"github.com/AstaFrode/go-libp2p/core/peer"
	"github.com/CESSProject/DeOSS/pkg/utils"
)

func (n *Node) findPeers(ch chan<- bool) {
	defer func() {
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
		ch <- true
	}()
	n.Discover("info", ">>>>> start findPeers <<<<<")
	for {
		if n.findPeer.Load() > 10 {
			n.findPeer.Store(0)
			err := n.findpeer()
			if err != nil {
				n.Discover("err", err.Error())
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
						n.GetDht().RoutingTable().TryAddPeer(foundPeer.ID, true, true)
						n.SavePeer(v.ID.Pretty(), peer.AddrInfo{
							ID:    v.ID,
							Addrs: v.Addrs,
						})
					}
				}
			}
		default:
			n.findPeer.Add(1)
			time.Sleep(time.Second)
		}
	}
}

func (n *Node) findpeer() error {
	peerChan, err := n.GetRoutingTable().FindPeers(
		n.GetCtxQueryFromCtxCancel(),
		n.GetRendezvousVersion(),
	)
	if err != nil {
		return err
	}

	for onePeer := range peerChan {
		if onePeer.ID == n.ID() {
			continue
		}
		err := n.Connect(n.GetCtxQueryFromCtxCancel(), onePeer)
		if err != nil {
			n.GetDht().RoutingTable().RemovePeer(onePeer.ID)
		} else {
			n.GetDht().RoutingTable().TryAddPeer(onePeer.ID, true, true)
			n.SavePeer(onePeer.ID.Pretty(), peer.AddrInfo{
				ID:    onePeer.ID,
				Addrs: onePeer.Addrs,
			})
		}
	}
	return nil
}
