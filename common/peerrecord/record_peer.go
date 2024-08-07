/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package peerrecord

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/libp2p/go-libp2p/core/peer"
)

type PeerRecord interface {
	// SavePeer saves or updates peer information
	SavePeer(addr peer.AddrInfo) error
	//
	SavePeerAccount(account string, peerid string) error
	//
	HasPeer(peerid string) bool
	//
	GetPeer(peerid string) (peer.AddrInfo, bool)
	//
	GetPeerByAccount(account string) (peer.AddrInfo, bool)
	//
	GetAllPeerId() []string
	//
	BackupPeer(path string) error
	//
	LoadPeer(path string) error
}

type PeerRecordType struct {
	lock        *sync.RWMutex
	accLock     *sync.RWMutex
	peerList    map[string]peer.AddrInfo
	accountList map[string]peer.AddrInfo
}

var _ PeerRecord = (*PeerRecordType)(nil)

func NewPeerRecord() PeerRecord {
	return &PeerRecordType{
		lock:        new(sync.RWMutex),
		accLock:     new(sync.RWMutex),
		peerList:    make(map[string]peer.AddrInfo, 100),
		accountList: make(map[string]peer.AddrInfo, 100),
	}
}

func (p *PeerRecordType) SavePeer(addr peer.AddrInfo) error {
	peerid := addr.ID.String()
	if peerid == "" {
		return errors.New("peer id is empty")
	}

	if addr.Addrs == nil {
		return errors.New("peer addrs is nil")
	}

	p.lock.Lock()
	p.peerList[peerid] = addr
	p.lock.Unlock()

	return nil
}

func (p PeerRecordType) SavePeerAccount(account string, peerid string) error {
	p.lock.RLock()
	addr, ok := p.peerList[peerid]
	p.lock.RUnlock()
	if !ok {
		return fmt.Errorf("not fount peer: %s", peerid)
	}
	p.accLock.Lock()
	p.accountList[account] = addr
	p.accLock.Unlock()
	return nil
}

func (p *PeerRecordType) HasPeer(peerid string) bool {
	p.lock.RLock()
	_, ok := p.peerList[peerid]
	p.lock.RUnlock()
	return ok
}

func (p *PeerRecordType) GetPeer(peerid string) (peer.AddrInfo, bool) {
	p.lock.RLock()
	addr, ok := p.peerList[peerid]
	p.lock.RUnlock()
	return addr, ok
}

func (p *PeerRecordType) GetPeerByAccount(account string) (peer.AddrInfo, bool) {
	p.accLock.RLock()
	addr, ok := p.accountList[account]
	p.accLock.RUnlock()
	return addr, ok
}

func (p *PeerRecordType) GetAllPeerId() []string {
	var result = make([]string, len(p.peerList))
	p.lock.RLock()
	defer p.lock.RUnlock()
	var i int
	for k := range p.peerList {
		result[i] = k
		i++
	}
	return result
}

func (p *PeerRecordType) BackupPeer(path string) error {
	p.lock.RLock()
	buf, err := json.Marshal(p.peerList)
	if err != nil {
		p.lock.RUnlock()
		return err
	}
	p.lock.RUnlock()
	err = sutils.WriteBufToFile(buf, path)
	return err
}

func (p *PeerRecordType) LoadPeer(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data = make(map[string]peer.AddrInfo)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		return err
	}
	p.lock.Lock()
	p.peerList = data
	p.lock.Unlock()
	return nil
}
