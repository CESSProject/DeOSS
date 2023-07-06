/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"log"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	ma "github.com/multiformats/go-multiaddr"
)

func (n *Node) sdkMgt(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Log("info", ">>>>> Start sdkMgt task")

	var err error

	var maAddr ma.Multiaddr
	var addrInfo *peer.AddrInfo
	var bootstrap []string
	//var linuxFileAttr *syscall.Stat_t

	tick_BlockInterval := time.NewTicker(pattern.BlockInterval * 30)
	defer tick_BlockInterval.Stop()

	tick_60s := time.NewTicker(time.Minute)
	defer tick_60s.Stop()

	boots := n.GetBootNodes()
	for _, b := range boots {
		temp, err := sutils.ParseMultiaddrs(b)
		if err != nil {
			n.Log("err", fmt.Sprintf("[ParseMultiaddrs %v] %v", b, err))
			continue
		}
		bootstrap = append(bootstrap, temp...)
	}
	n.Log("info", fmt.Sprintf("bootnode list:  %s", bootstrap))

	for {
		select {
		case <-tick_BlockInterval.C:
			if !n.GetChainState() {
				n.Log("err", pattern.ERR_RPC_CONNECTION.Error())
				err = n.Reconnect()
				if err != nil {
					log.Println(pattern.ERR_RPC_CONNECTION)
					n.Log("err", pattern.ERR_RPC_CONNECTION.Error())
				} else {
					log.Println("rpc reconnection successful")
					n.Log("info", "rpc reconnection successfully")
				}
			}
		case <-tick_60s.C:
			for _, v := range bootstrap {
				maAddr, err = ma.NewMultiaddr(v)
				if err != nil {
					continue
				}
				addrInfo, err = peer.AddrInfoFromP2pAddr(maAddr)
				if err != nil {
					continue
				}
				err = n.Connect(n.GetRootCtx(), *addrInfo)
				if err != nil {
					continue
				}
				//n.Log("info", fmt.Sprintf("connect to bootnode: %s", addrInfo.ID.Pretty()))
				n.SavePeer(addrInfo.ID.Pretty(), *addrInfo)
			}
			// if !n.GetDiscoverSt() {
			// 	n.StartDiscover()
			// }
			// Delete files that have not been accessed for more than 30 days
			// files, _ = filepath.Glob(filepath.Join(n.GetDirs().FileDir, "/*"))
			// for _, v := range files {
			// 	fs, err := os.Stat(v)
			// 	if err == nil {
			// 		linuxFileAttr = fs.Sys().(*syscall.Stat_t)
			// 		if time.Since(time.Unix(linuxFileAttr.Atim.Sec, 0)).Hours() > configs.FileCacheExpirationTime {
			// 			os.Remove(v)
			// 		}
			// 	}
			// }
		}
	}
}
