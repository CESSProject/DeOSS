/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package tracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// MinTrackerInfoLength = len(json.Marshal(TrackerInfo{}))
const MinTrackerInfoLength = 223

type TrackerInfo struct {
	Segment       []chain.SegmentDataInfo `json:"segment"`
	Owner         []byte                  `json:"owner"`
	ShuntMiner    []string                `json:"shunt_miner"`
	Points        coordinate.Range        `json:"range"`
	Fid           string                  `json:"fid"`
	FileName      string                  `json:"file_name"`
	BucketName    string                  `json:"bucket_name"`
	TerritoryName string                  `json:"territory_name"`
	CacheDir      string                  `json:"cache_dir"`
	Cipher        string                  `json:"cipher"`
	FileSize      uint64                  `json:"file_size"`
}

type TrackerInfov1 struct {
	Segment       []chain.SegmentDataInfo `json:"segment"`
	Owner         []byte                  `json:"owner"`
	ShuntMiner    ShuntMiner              `json:"shunt_miner"`
	Points        coordinate.Range        `json:"range"`
	Fid           string                  `json:"fid"`
	FileName      string                  `json:"file_name"`
	BucketName    string                  `json:"bucket_name"`
	TerritoryName string                  `json:"territory_name"`
	CacheDir      string                  `json:"cache_dir"`
	Cipher        string                  `json:"cipher"`
	FileSize      uint64                  `json:"file_size"`
	PutFlag       bool                    `json:"put_flag"`
}

type ShuntMiner struct {
	Miners   []string `json:"miners"`
	Complete []bool   `json:"complete"`
}

type Tracker interface {
	AddToTraceFile(fid string, t TrackerInfo) error
	ParsingTraceFile(fid string) (TrackerInfo, error)
	HasTraceFile(fid string) bool
	ListTraceFiles() ([]string, error)
	GetNumbersTrackFiles(number int) ([]string, error)
	DeleteTraceFile(fid string)
}

type Track struct {
	lock *sync.Mutex
	dir  string
}

var _ Tracker = (*Track)(nil)

func NewTracker(dir string) Tracker {
	return &Track{
		lock: new(sync.Mutex),
		dir:  dir,
	}
}

func (n *Track) AddToTraceFile(fid string, t TrackerInfo) error {
	if len(fid) != chain.FileHashLen {
		return errors.New("invalid fid")
	}
	var err error
	data, err := json.Marshal(&t)
	if err != nil {
		return err
	}

	fpath := filepath.Join(n.dir, uuid.New().String())
	for {
		_, err = os.Stat(fpath)
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)
		fpath = filepath.Join(n.dir, uuid.New().String())
	}
	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "[os.Create]")
	}
	defer os.Remove(fpath)

	_, err = f.Write(data)
	if err != nil {
		f.Close()
		return errors.Wrap(err, "[Write]")
	}
	err = f.Sync()
	if err != nil {
		f.Close()
		return errors.Wrap(err, "[Sync]")
	}
	f.Close()
	err = os.Rename(fpath, filepath.Join(n.dir, fid))
	return err
}

func (n *Track) ParsingTraceFile(fid string) (TrackerInfo, error) {
	var result TrackerInfo
	n.lock.Lock()
	b, err := os.ReadFile(filepath.Join(n.dir, fid))
	if err != nil {
		n.lock.Unlock()
		return result, err
	}
	n.lock.Unlock()

	err = json.Unmarshal(b, &result)
	if err != nil {
		var resultv1 TrackerInfov1
		err = json.Unmarshal(b, &resultv1)
		if err != nil {
			return result, err
		}
		result.Segment = resultv1.Segment
		result.Owner = resultv1.Owner
		result.Points = resultv1.Points
		result.ShuntMiner = resultv1.ShuntMiner.Miners
		result.Fid = resultv1.Fid
		result.FileName = resultv1.FileName
		result.BucketName = resultv1.BucketName
		result.TerritoryName = resultv1.TerritoryName
		result.CacheDir = resultv1.CacheDir
		result.Cipher = resultv1.Cipher
		result.FileSize = resultv1.FileSize
		return result, nil
	}
	return result, err
}

func (n *Track) HasTraceFile(fid string) bool {
	n.lock.Lock()
	_, err := os.Stat(filepath.Join(n.dir, fid))
	n.lock.Unlock()
	return err == nil
}

func (n *Track) ListTraceFiles() ([]string, error) {
	n.lock.Lock()
	result, err := filepath.Glob(filepath.Join(n.dir, "*"))
	if err != nil {
		n.lock.Unlock()
		return nil, err
	}
	n.lock.Unlock()
	return result, nil
}

func (n *Track) GetNumbersTrackFiles(number int) ([]string, error) {
	if number <= 0 {
		return []string{}, nil
	}

	var listFile []string
	err := filepath.WalkDir(n.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if len(filepath.Base(path)) == chain.FileHashLen {
				listFile = append(listFile, path)
				if len(listFile) >= number {
					return errors.New("founded")
				}
			}
		}
		return nil
	})
	return listFile, err
}

func (n *Track) DeleteTraceFile(fid string) {
	n.lock.Lock()
	os.Remove(filepath.Join(n.dir, fid))
	n.lock.Unlock()
}
