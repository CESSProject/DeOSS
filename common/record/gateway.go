/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package record

import "sync"

type GatewayRecorder interface {
	SaveGatewayRecord(account, addr string)
	GetAllGatewayAddrs() []string
}

type GatewayRecord struct {
	gwlistLock *sync.RWMutex
	gwlist     map[string]string
}

var _ GatewayRecorder = (*GatewayRecord)(nil)

func NewGatewayRecord() GatewayRecorder {
	return &GatewayRecord{
		gwlistLock: new(sync.RWMutex),
		gwlist:     make(map[string]string, 10),
	}
}

func (g *GatewayRecord) SaveGatewayRecord(account, addr string) {
	g.gwlistLock.Lock()
	g.gwlist[account] = addr
	g.gwlistLock.Unlock()
}

func (g *GatewayRecord) GetAllGatewayAddrs() []string {
	var i int
	g.gwlistLock.RLock()
	var value = make([]string, len(g.gwlist))
	for _, v := range g.gwlist {
		value[i] = v
		i++
	}
	g.gwlistLock.RUnlock()
	return value
}
