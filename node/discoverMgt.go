/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/p2p-go/core"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
)

func (n *Node) subscribe(ch chan<- bool) {
	defer func() {
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
		ch <- true
	}()
	n.Discover("info", ">>>>> start subscribe <<<<<")

	var (
		err      error
		findpeer peer.AddrInfo
	)

	gossipSub, err := pubsub.NewGossipSub(context.Background(), n.GetHost())
	if err != nil {
		return
	}

	// join the pubsub topic called librum
	topic, err := gossipSub.Join(core.NetworkRoom)
	if err != nil {
		return
	}

	// subscribe to topic
	subscriber, err := topic.Subscribe()
	if err != nil {
		return
	}

	for {
		msg, err := subscriber.Next(context.Background())
		if err != nil {
			panic(err)
		}

		// only consider messages delivered by other peers
		if msg.ReceivedFrom == n.ID() {
			continue
		}

		err = json.Unmarshal(msg.Data, &findpeer)
		if err != nil {
			continue
		}
		n.SavePeerDecorator(findpeer.ID.String(), findpeer)
	}
}

func (n *Node) discover() {
	var routingDiscovery = drouting.NewRoutingDiscovery(n.GetDHTable())
	rendezvous := n.GetRendezvousVersion()
	h := n.GetHost()
	dutil.Advertise(context.Background(), routingDiscovery, rendezvous)

	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()

	for {
		<-ticker.C
		peers, err := routingDiscovery.FindPeers(context.Background(), rendezvous)
		if err != nil {
			log.Fatal(err)
		}

		for p := range peers {
			if p.ID == h.ID() {
				continue
			}
			if h.Network().Connectedness(p.ID) != network.Connected {
				_, err = h.Network().DialPeer(context.Background(), p.ID)
				if err != nil {
					continue
				}
			}
			n.SavePeerDecorator(p.ID.String(), p)
		}
	}
}
