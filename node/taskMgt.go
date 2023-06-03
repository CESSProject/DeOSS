/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

func (n *Node) TaskMgt() {
	var (
		ch_trackFile = make(chan bool, 1)
		ch_spaceMgt  = make(chan bool, 1)
	)

	go n.trackFile(ch_trackFile)
	go n.spaceMgt(ch_spaceMgt)

	for {
		select {
		case <-ch_trackFile:
			go n.trackFile(ch_trackFile)
		case <-ch_spaceMgt:
			go n.spaceMgt(ch_spaceMgt)
		}
	}
}
