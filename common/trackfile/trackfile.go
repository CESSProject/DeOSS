/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package trackfile

import (
	"errors"
	"sync"

	"github.com/CESSProject/DeOSS/configs"
)

type TrackFile interface {
	AddTrackFile(fid string) error
	GetTrackFileNum() int
	DelTrackFile(fid string)
}

type TrackFileType struct {
	lock       *sync.RWMutex
	trackFiles map[string]struct{}
}

var _ TrackFile = (*TrackFileType)(nil)

func NewTeeRecord() TrackFile {
	return &TrackFileType{
		lock:       new(sync.RWMutex),
		trackFiles: make(map[string]struct{}, configs.MaxTrackThread),
	}
}

func (t *TrackFileType) AddTrackFile(fid string) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	if len(t.trackFiles) >= configs.MaxTrackThread {
		return errors.New("track queue is full")
	}
	_, ok := t.trackFiles[fid]
	if ok {
		return errors.New("already in track")
	}
	t.trackFiles[fid] = struct{}{}
	return nil
}

func (t *TrackFileType) GetTrackFileNum() int {
	t.lock.RLock()
	result := len(t.trackFiles)
	t.lock.RUnlock()
	return result
}

func (t *TrackFileType) DelTrackFile(fid string) {
	t.lock.Lock()
	delete(t.trackFiles, fid)
	t.lock.Unlock()
}
