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
	tickDiscover := time.NewTicker(time.Minute * 3)
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
		case peer, _ := <-n.GetDiscoveredPeers():
			if limit.Allow() {
				n.Discover("info", "reset")
				tickDiscover.Reset(time.Minute * 3)
			}
			if len(peer.Responses) == 0 {
				break
			}
			for _, v := range peer.Responses {
				n.SavePeer(v.ID.Pretty(), *v)
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
