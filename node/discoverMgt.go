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

	"github.com/CESSProject/sdk-go/core/pattern"
	sutils "github.com/CESSProject/sdk-go/core/utils"
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

	var ok bool
	var err error
	var peerid string
	var addr string
	var multiaddr string
	var id peer.ID
	var allPeers map[string][]ma.Multiaddr

	tick_30s := time.NewTicker(time.Second * 30)
	defer tick_30s.Stop()

	tick_60s := time.NewTicker(time.Minute)
	defer tick_60s.Stop()

	for {
		select {
		case <-tick_30s.C:
			ok, err = n.NetListening()
			if !ok || err != nil {
				n.Discover("err", pattern.ERR_RPC_CONNECTION.Error())
				n.SetChainState(false)
				err = n.Reconnect()
				if err != nil {
					log.Println(pattern.ERR_RPC_CONNECTION)
				} else {
					n.Discover("info", "reconnected successfully")
				}
			}
		case <-tick_60s.C:
			allPeers = n.GetAllPeer()
			for k, v := range allPeers {
				id, err = peer.Decode(k)
				if err != nil {
					continue
				}
				addrInfo := peer.AddrInfo{
					ID:    id,
					Addrs: v,
				}
				n.Connect(n.GetRootCtx(), addrInfo)
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
			n.PutPeer(peerid, discoverPeer.Addrs)

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
	}
}
