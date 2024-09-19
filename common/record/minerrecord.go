/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package record

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/libp2p/go-libp2p/core/peer"
)

type MinerRecorder interface {
	// SavePeer saves or updates peer information
	SavePeer(addr string) error
	//
	DeletePeer(addr string)
	//
	DeletePeerByAccount(acc string)
	//
	SavePeerAccount(account string, peerid string, state string, idle_space uint64) error
	//
	HasPeer(peerid string) bool
	//
	GetPeer(peerid string) (peer.AddrInfo, bool)
	//
	GetPeerByAccount(account string) (AccountInfo, bool)
	//
	GetAccountByPeer(peerid string) (string, bool)
	//
	GetAllPeerId() []string
	//
	GetAllWhitelist() []string
	//
	AddToWhitelist(peerid, account string)
	//
	AddToBlacklist(peerid, account, reason string)
	//
	RemoveFromBlacklist(peerid string)
	//
	IsInBlacklist(peerid string) bool
	//
	GetBlacklist() map[string]BlacklistInfo
	//
	GetBlacklistInfo(peerid string) (BlacklistInfo, bool)
	//
	BackupPeer(path string) error
	//
	LoadPeer(path string) error
	//
	BackupAccountPeer(path string) error
	//
	LoadAccountPeer(path string) error
	//
	BackupBlacklist(path string) error
	//
	LoadBlacklist(path string) error
	//
	BackupWhitelist(path string) error
	//
	LoadWhitelist(path string) error
}

type MinerRecord struct {
	lock            *sync.RWMutex
	accLock         *sync.RWMutex
	blacklistLock   *sync.RWMutex
	whitelistLock   *sync.RWMutex
	peerAccountLock *sync.RWMutex
	peerList        map[string]peer.AddrInfo
	peerAccountList map[string]string
	accountList     map[string]AccountInfo
	blacklist       map[string]BlacklistInfo
	whitelist       map[string]string
}

type AccountInfo struct {
	Account   string        `json:"account"`
	State     string        `json:"state"`
	IdleSpace uint64        `json:"idle_space"`
	Addrs     peer.AddrInfo `json:"addrs"`
}

type BlacklistInfo struct {
	Account string        `json:"account"`
	Reason  string        `json:"reason"`
	Addrs   peer.AddrInfo `json:"addrs"`
}

var _ MinerRecorder = (*MinerRecord)(nil)

func NewMinerRecord() MinerRecorder {
	return &MinerRecord{
		lock:            new(sync.RWMutex),
		accLock:         new(sync.RWMutex),
		blacklistLock:   new(sync.RWMutex),
		whitelistLock:   new(sync.RWMutex),
		peerAccountLock: new(sync.RWMutex),
		peerList:        make(map[string]peer.AddrInfo, 100),
		peerAccountList: make(map[string]string, 100),
		accountList:     make(map[string]AccountInfo, 100),
		blacklist:       make(map[string]BlacklistInfo, 100),
		whitelist:       make(map[string]string, 100),
	}
}

func (p *MinerRecord) SavePeer(addr peer.AddrInfo) error {
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

func (p *MinerRecord) DeletePeer(peerid string) {
	p.lock.Lock()
	delete(p.peerList, peerid)
	p.lock.Unlock()

	p.blacklistLock.Lock()
	delete(p.blacklist, peerid)
	p.blacklistLock.Unlock()
}

func (p *MinerRecord) DeletePeerByAccount(acc string) {
	p.accLock.RLock()
	value, ok := p.accountList[acc]
	p.accLock.RUnlock()
	if ok {
		p.DeletePeer(value.Addrs.ID.String())
	}
}

func (p *MinerRecord) SavePeerAccount(account string, peerid string, state string, idle_space uint64) error {
	p.lock.RLock()
	addr, ok := p.peerList[peerid]
	p.lock.RUnlock()
	if !ok {
		return fmt.Errorf("not fount peer: %s", peerid)
	}

	p.accLock.Lock()
	p.accountList[account] = AccountInfo{
		Addrs:     addr,
		Account:   account,
		State:     state,
		IdleSpace: idle_space,
	}
	p.accLock.Unlock()

	p.peerAccountLock.Lock()
	p.peerAccountList[peerid] = account
	p.peerAccountLock.Unlock()

	p.blacklistLock.Lock()
	value, ok := p.blacklist[peerid]
	if ok {
		value.Account = account
		p.blacklist[peerid] = value
	}
	p.blacklistLock.Unlock()
	return nil
}

func (p *MinerRecord) HasPeer(peerid string) bool {
	p.lock.RLock()
	_, ok := p.peerList[peerid]
	p.lock.RUnlock()
	return ok
}

func (p *MinerRecord) GetPeer(peerid string) (peer.AddrInfo, bool) {
	p.lock.RLock()
	addr, ok := p.peerList[peerid]
	p.lock.RUnlock()
	return addr, ok
}

func (p *MinerRecord) GetPeerByAccount(account string) (AccountInfo, bool) {
	p.accLock.RLock()
	accountInfo, ok := p.accountList[account]
	p.accLock.RUnlock()
	return accountInfo, ok
}

func (p *MinerRecord) GetAccountByPeer(peerid string) (string, bool) {
	p.peerAccountLock.RLock()
	acc, ok := p.peerAccountList[peerid]
	p.peerAccountLock.RUnlock()
	return acc, ok
}

func (p *MinerRecord) GetAllPeerId() []string {
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

func (p *MinerRecord) GetAllWhitelist() []string {
	var i int
	p.whitelistLock.RLock()
	var result = make([]string, len(p.whitelist))
	for k := range p.whitelist {
		result[i] = k
		i++
	}
	p.whitelistLock.RUnlock()
	return result
}

func (p *MinerRecord) AddToWhitelist(peerid, account string) {
	p.whitelistLock.Lock()
	p.whitelist[peerid] = account
	p.whitelistLock.Unlock()

	p.blacklistLock.Lock()
	delete(p.blacklist, peerid)
	p.blacklistLock.Unlock()
}

func (p *MinerRecord) AddToBlacklist(peerid, account, reason string) {
	p.lock.RLock()
	addrs, _ := p.peerList[peerid]
	p.lock.RUnlock()

	p.blacklistLock.Lock()
	p.blacklist[peerid] = BlacklistInfo{
		Addrs:   addrs,
		Account: account,
		Reason:  reason,
	}
	p.blacklistLock.Unlock()

	p.whitelistLock.Lock()
	delete(p.whitelist, peerid)
	p.whitelistLock.Unlock()
}

func (p *MinerRecord) RemoveFromBlacklist(peerid string) {
	p.blacklistLock.Lock()
	delete(p.blacklist, peerid)
	p.blacklistLock.Unlock()
}

func (p *MinerRecord) IsInBlacklist(peerid string) bool {
	p.blacklistLock.RLock()
	_, ok := p.blacklist[peerid]
	p.blacklistLock.RUnlock()
	return ok
}

func (p *MinerRecord) GetBlacklist() map[string]BlacklistInfo {
	p.blacklistLock.Lock()
	var result = make(map[string]BlacklistInfo, len(p.blacklist))
	for k, v := range p.blacklist {
		result[k] = v
	}
	p.blacklistLock.Unlock()
	return result
}

func (p *MinerRecord) GetBlacklistInfo(peerid string) (BlacklistInfo, bool) {
	p.blacklistLock.RLock()
	result, ok := p.blacklist[peerid]
	p.blacklistLock.RUnlock()
	return result, ok
}

func (p *MinerRecord) BackupPeer(path string) error {
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

func (p *MinerRecord) LoadPeer(path string) error {
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

func (p *MinerRecord) BackupAccountPeer(path string) error {
	p.accLock.RLock()
	buf, err := json.Marshal(p.accountList)
	if err != nil {
		p.accLock.RUnlock()
		return err
	}
	p.accLock.RUnlock()
	err = sutils.WriteBufToFile(buf, path)
	return err
}

func (p *MinerRecord) LoadAccountPeer(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data = make(map[string]AccountInfo)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		return err
	}
	p.accLock.Lock()
	p.accountList = data
	p.accLock.Unlock()
	return nil
}

func (p *MinerRecord) BackupBlacklist(path string) error {
	p.blacklistLock.RLock()
	buf, err := json.Marshal(p.blacklist)
	if err != nil {
		p.blacklistLock.RUnlock()
		return err
	}
	p.blacklistLock.RUnlock()
	err = sutils.WriteBufToFile(buf, path)
	return err
}

func (p *MinerRecord) LoadBlacklist(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data = make(map[string]BlacklistInfo)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		return err
	}
	p.blacklistLock.Lock()
	p.blacklist = data
	p.blacklistLock.Unlock()
	return nil
}

func (p *MinerRecord) BackupWhitelist(path string) error {
	p.whitelistLock.RLock()
	buf, err := json.Marshal(p.whitelist)
	if err != nil {
		p.whitelistLock.RUnlock()
		return err
	}
	p.whitelistLock.RUnlock()
	err = sutils.WriteBufToFile(buf, path)
	return err
}

func (p *MinerRecord) LoadWhitelist(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data = make(map[string]string)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		return err
	}
	p.whitelistLock.Lock()
	p.whitelist = data
	p.whitelistLock.Unlock()
	return nil
}
