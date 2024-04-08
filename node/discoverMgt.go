/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"encoding/json"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/p2p-go/core"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
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

		n.SavePeer(findpeer.ID.String(), findpeer)
	}
}
