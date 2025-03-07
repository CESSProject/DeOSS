/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package record

import (
	"encoding/json"
	"os"
	"strings"
	"sync"

	sutils "github.com/CESSProject/cess-go-sdk/utils"
)

type MinerRecorder interface {
	// SaveMinerinfo add or update miner information
	SaveMinerinfo(account string, addr string, state string, idle_space uint64)

	// DeleteMinerinfo delete miner information
	DeleteMinerinfo(account string)

	// HasMinerinfo whether miner information is recorded
	HasMinerinfo(account string) bool

	//
	GetMinerinfo(account string) (Minerinfo, bool)

	//
	GetAllMinerAccount() []string

	//
	GetAllMinerinfos() []Minerinfo

	//
	GetAllWhitelist() []string

	//
	GetAllWhitelistInfos() []Minerinfo

	//
	AddToWhitelist(account string, info Minerinfo)

	//
	AddToBlacklist(account, addr, reason string)

	//
	RemoveFromBlacklist(account string)

	//
	IsInBlacklist(account string) bool

	//
	GetAllBlacklist() map[string]Reason

	//
	GetBlacklistInfo(account string) (Reason, bool)

	//
	BackupMinerlist(path string) error

	//
	LoadMinerlist(path string) error

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
	minerlistLock *sync.RWMutex
	blacklistLock *sync.RWMutex
	whitelistLock *sync.RWMutex

	minerlist map[string]Minerinfo
	blacklist map[string]Reason
	whitelist map[string]Minerinfo
}

type Minerinfo struct {
	Account   string `json:"account"`
	State     string `json:"state"`
	Addr      string `json:"addr"`
	Idlespace uint64 `json:"idlespace"`
}

type Reason struct {
	Account string `json:"account"`
	Reason  string `json:"reason"`
	Addr    string `json:"addr"`
}

var _ MinerRecorder = (*MinerRecord)(nil)

func NewMinerRecord() MinerRecorder {
	return &MinerRecord{
		minerlistLock: new(sync.RWMutex),
		blacklistLock: new(sync.RWMutex),
		whitelistLock: new(sync.RWMutex),

		minerlist: make(map[string]Minerinfo, 100),
		blacklist: make(map[string]Reason, 100),
		whitelist: make(map[string]Minerinfo, 100),
	}
}

func (m *MinerRecord) SaveMinerinfo(account string, addr string, state string, idlespace uint64) {
	m.minerlistLock.Lock()
	m.minerlist[account] = Minerinfo{
		Account:   account,
		State:     state,
		Addr:      addr,
		Idlespace: idlespace,
	}
	m.minerlistLock.Unlock()

	if addr == "" {
		m.AddToBlacklist(account, addr, "miner addr is empty")
	}

	if strings.Contains(addr, "1.1.1.") ||
		strings.Contains(addr, "0.0.0.") ||
		strings.Contains(addr, " ") {
		m.AddToBlacklist(account, addr, "miner addr is invalid")
	}

	m.whitelistLock.Lock()
	_, ok := m.whitelist[account]
	if ok {
		m.whitelist[account] = Minerinfo{
			Account:   account,
			State:     state,
			Addr:      addr,
			Idlespace: idlespace,
		}
	}
	m.whitelistLock.Unlock()
}

func (m *MinerRecord) DeleteMinerinfo(account string) {
	m.minerlistLock.Lock()
	delete(m.minerlist, account)
	m.minerlistLock.Unlock()

	m.blacklistLock.Lock()
	delete(m.blacklist, account)
	m.blacklistLock.Unlock()
}

func (m *MinerRecord) HasMinerinfo(account string) bool {
	m.minerlistLock.RLock()
	_, ok := m.minerlist[account]
	m.minerlistLock.RUnlock()
	return ok
}

func (m *MinerRecord) GetMinerinfo(account string) (Minerinfo, bool) {
	m.minerlistLock.RLock()
	value, ok := m.minerlist[account]
	m.minerlistLock.RUnlock()
	return value, ok
}

func (m *MinerRecord) GetAllMinerAccount() []string {
	m.minerlistLock.RLock()
	var result = make([]string, len(m.minerlist))
	i := 0
	for k := range m.minerlist {
		result[i] = k
		i++
	}
	m.minerlistLock.RUnlock()
	return result
}

func (m *MinerRecord) GetAllMinerinfos() []Minerinfo {
	m.minerlistLock.RLock()
	var result = make([]Minerinfo, len(m.minerlist))
	i := 0
	for _, v := range m.minerlist {
		result[i] = v
		i++
	}
	m.minerlistLock.RUnlock()
	return result
}

func (m *MinerRecord) GetAllWhitelist() []string {
	var i int
	m.whitelistLock.RLock()
	var result = make([]string, len(m.whitelist))
	for k := range m.whitelist {
		result[i] = k
		i++
	}
	m.whitelistLock.RUnlock()
	return result
}

func (m *MinerRecord) GetAllWhitelistInfos() []Minerinfo {
	var i int
	m.whitelistLock.RLock()
	var result = make([]Minerinfo, len(m.whitelist))
	for _, v := range m.whitelist {
		result[i] = v
		i++
	}
	m.whitelistLock.RUnlock()
	return result
}

func (m *MinerRecord) AddToWhitelist(account string, info Minerinfo) {
	m.whitelistLock.Lock()
	m.whitelist[account] = info
	m.whitelistLock.Unlock()

	m.blacklistLock.Lock()
	delete(m.blacklist, account)
	m.blacklistLock.Unlock()
}

func (m *MinerRecord) AddToBlacklist(account, addr, reason string) {
	msg := strings.ReplaceAll(reason, "\"", "")
	m.blacklistLock.Lock()
	m.blacklist[account] = Reason{
		Account: account,
		Reason:  msg,
		Addr:    addr,
	}
	m.blacklistLock.Unlock()

	m.whitelistLock.Lock()
	delete(m.whitelist, account)
	m.whitelistLock.Unlock()
}

func (m *MinerRecord) RemoveFromBlacklist(account string) {
	m.blacklistLock.Lock()
	delete(m.blacklist, account)
	m.blacklistLock.Unlock()
}

func (m *MinerRecord) IsInBlacklist(account string) bool {
	m.blacklistLock.RLock()
	_, ok := m.blacklist[account]
	m.blacklistLock.RUnlock()
	return ok
}

func (m *MinerRecord) GetAllBlacklist() map[string]Reason {
	m.blacklistLock.Lock()
	var result = make(map[string]Reason, len(m.blacklist))
	for k, v := range m.blacklist {
		result[k] = v
	}
	m.blacklistLock.Unlock()
	return result
}

func (m *MinerRecord) GetBlacklistInfo(account string) (Reason, bool) {
	m.blacklistLock.RLock()
	result, ok := m.blacklist[account]
	m.blacklistLock.RUnlock()
	return result, ok
}

func (m *MinerRecord) BackupMinerlist(path string) error {
	m.minerlistLock.RLock()
	buf, err := json.Marshal(m.minerlist)
	if err != nil {
		m.minerlistLock.RUnlock()
		return err
	}
	m.minerlistLock.RUnlock()
	err = sutils.WriteBufToFile(buf, path)
	return err
}

func (m *MinerRecord) LoadMinerlist(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data = make(map[string]Minerinfo)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		return err
	}
	m.minerlistLock.Lock()
	m.minerlist = data
	m.minerlistLock.Unlock()
	return nil
}

func (m *MinerRecord) BackupBlacklist(path string) error {
	m.blacklistLock.RLock()
	buf, err := json.Marshal(m.blacklist)
	if err != nil {
		m.blacklistLock.RUnlock()
		return err
	}
	m.blacklistLock.RUnlock()
	err = sutils.WriteBufToFile(buf, path)
	return err
}

func (m *MinerRecord) LoadBlacklist(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data = make(map[string]Reason)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		return err
	}
	m.blacklistLock.Lock()
	m.blacklist = data
	m.blacklistLock.Unlock()
	return nil
}

func (m *MinerRecord) BackupWhitelist(path string) error {
	m.whitelistLock.RLock()
	buf, err := json.Marshal(m.whitelist)
	if err != nil {
		m.whitelistLock.RUnlock()
		return err
	}
	m.whitelistLock.RUnlock()
	err = sutils.WriteBufToFile(buf, path)
	return err
}

func (m *MinerRecord) LoadWhitelist(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data = make(map[string]Minerinfo)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		return err
	}
	m.whitelistLock.Lock()
	m.whitelist = data
	m.whitelistLock.Unlock()
	return nil
}
