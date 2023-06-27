/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

func (n *Node) TaskMgt() {
	var (
		ch_trackFile   = make(chan bool, 1)
		ch_discoverMgt = make(chan bool, 1)
	)

	go n.tracker(ch_trackFile)
	go n.discoverMgt(ch_discoverMgt)

	for {
		select {
		case <-ch_trackFile:
			go n.tracker(ch_trackFile)
		case <-ch_discoverMgt:
			go n.discoverMgt(ch_discoverMgt)
		}
	}
}
