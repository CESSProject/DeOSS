/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
)

type RecordInfo struct {
	SegmentInfo []pattern.SegmentDataInfo `json:"segmentInfo"`
	Owner       []byte                    `json:"owner"`
	Roothash    string                    `json:"roothash"`
	Filename    string                    `json:"filename"`
	Buckname    string                    `json:"buckname"`
	Filesize    uint64                    `json:"filesize"`
	Putflag     bool                      `json:"putflag"`
	Count       uint8                     `json:"count"`
	Duplicate   bool                      `json:"duplicate"`
}

// MinRecordInfoLength = len(json.Marshal(RecordInfo{}))
const MinRecordInfoLength = 132

// tracker
func (n *Node) tracker(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Track("info", ">>>>> start tracker <<<<<")

	var err error
	var recordErr string
	var trackFiles []string

	for {
		trackFiles, err = n.ListTrackFiles()
		if err != nil {
			if err.Error() != recordErr {
				n.Track("err", err.Error())
				recordErr = err.Error()
			}
			time.Sleep(pattern.BlockInterval)
			continue
		}
		for _, v := range trackFiles {
			err = n.trackFile(v)
			if err != nil {
				if err.Error() != recordErr {
					n.Track("err", err.Error())
					recordErr = err.Error()
				}
			}
		}
		time.Sleep(time.Minute)
	}
}

func (n *Node) trackFile(trackfile string) error {
	var (
		err          error
		count        uint8
		roothash     string
		b            []byte
		recordFile   RecordInfo
		storageorder pattern.StorageOrder
	)

	roothash = filepath.Base(trackfile)
	b, err = n.Get([]byte("transfer:" + roothash))
	if err == nil {
		storageorder, err = n.QueryStorageOrder(roothash)
		if err != nil {
			if err.Error() != pattern.ERR_Empty {
				return errors.Wrapf(err, "[%s] [QueryStorageOrder]", roothash)
			}
			_, err = n.QueryFileMetadata(roothash)
			if err != nil {
				if err.Error() != pattern.ERR_Empty {
					return errors.Wrapf(err, "[%s] [QueryFileMetadata]", roothash)
				}
				n.Delete([]byte("transfer:" + roothash))
				recordFile, err = n.ParseTrackFromFile(roothash)
				if err != nil {
					n.DeleteTrackFile(roothash)
					return errors.Wrapf(err, "[ParseTrackFromFile]")
				}
				recordFile.Putflag = false
				recordFile.Count = 0
				b, err = json.Marshal(&recordFile)
				if err != nil {
					return errors.Wrapf(err, "[%s] [json.Marshal]", roothash)
				}
				err = n.WriteTrackFile(roothash, b)
				if err != nil {
					return errors.Wrapf(err, "[%s] [WriteTrackFile]", roothash)
				}
				n.Delete([]byte("transfer:" + roothash))
			} else {
				n.Track("info", fmt.Sprintf("[%s] File storage success", roothash))
				recordFile, err = n.ParseTrackFromFile(roothash)
				if err == nil {
					if len(recordFile.SegmentInfo) > 0 {
						baseDir := filepath.Dir(recordFile.SegmentInfo[0].SegmentHash)
						os.Rename(filepath.Join(baseDir, roothash), filepath.Join(n.GetDirs().FileDir, roothash))
						os.RemoveAll(baseDir)
					}
				}
				n.DeleteTrackFile(roothash)
				n.Delete([]byte("transfer:" + roothash))
			}
			return nil
		}
	}

	recordFile, err = n.ParseTrackFromFile(roothash)
	if err != nil {
		return errors.Wrapf(err, "[ParseTrackFromFile]")
	}

	if roothash != recordFile.Roothash {
		n.DeleteTrackFile(roothash)
		return errors.Errorf("[%s] Recorded filehash [%s] error", roothash, recordFile.Roothash)
	}

	if recordFile.Putflag {
		if storageorder.AssignedMiner != nil {
			if uint8(storageorder.Count) == recordFile.Count {
				return nil
			}
		}
	}

	if recordFile.Duplicate {
		_, err = n.QueryFileMetadata(roothash)
		if err == nil {
			_, err = n.GenerateStorageOrder(recordFile.Roothash, nil, recordFile.Owner, recordFile.Filename, recordFile.Buckname, recordFile.Filesize)
			if err != nil {
				return errors.Wrapf(err, " [%s] [GenerateStorageOrder]", roothash)
			}
			if len(recordFile.SegmentInfo) > 0 {
				baseDir := filepath.Dir(recordFile.SegmentInfo[0].SegmentHash)
				os.Rename(filepath.Join(baseDir, roothash), filepath.Join(n.GetDirs().FileDir, roothash))
				os.RemoveAll(baseDir)
			}
			n.DeleteTrackFile(roothash)
			n.Track("info", fmt.Sprintf("[%s] Duplicate file declaration suc", roothash))
			return nil
		}
		_, err = n.QueryStorageOrder(recordFile.Roothash)
		if err != nil {
			if err.Error() != pattern.ERR_Empty {
				return errors.Wrapf(err, "[%s] [QueryStorageOrder]", roothash)
			}
			n.Track("info", fmt.Sprintf("[%s] Duplicate file become primary file", roothash))
			recordFile.Duplicate = false
			recordFile.Putflag = false
			b, err = json.Marshal(&recordFile)
			if err != nil {
				return errors.Wrapf(err, "[%s] [json.Marshal]", roothash)
			}
			err = n.WriteTrackFile(roothash, b)
			if err != nil {
				return errors.Wrapf(err, "[%s] [WriteTrackFile]", roothash)
			}
		}
		return nil
	}

	count, err = n.backupFiles(recordFile.Owner, recordFile.SegmentInfo, roothash, recordFile.Filename, recordFile.Buckname, recordFile.Filesize)
	if err != nil {
		return errors.Wrapf(err, "[%s] [backupFiles]", roothash)
	}

	n.Track("info", fmt.Sprintf("[%s] File successfully transferred to all allocated storage nodes", roothash))

	recordFile.Putflag = true
	recordFile.Count = count
	b, err = json.Marshal(&recordFile)
	if err != nil {
		return errors.Wrapf(err, "[%s] [json.Marshal]", roothash)
	}

	err = n.WriteTrackFile(roothash, b)
	if err != nil {
		return errors.Wrapf(err, "[%s] [WriteTrackFile]", roothash)
	}
	n.Cache.Put([]byte("transfer:"+roothash), []byte(fmt.Sprintf("%v", count)))
	return nil
}

func (n *Node) backupFiles(owner []byte, segmentInfo []pattern.SegmentDataInfo, roothash, filename, bucketname string, filesize uint64) (uint8, error) {
	var err error
	var storageOrder pattern.StorageOrder

	_, err = n.QueryFileMetadata(roothash)
	if err == nil {
		return 0, nil
	}

	for i := 0; i < 3; i++ {
		storageOrder, err = n.QueryStorageOrder(roothash)
		if err != nil {
			if err.Error() == pattern.ERR_Empty {
				_, err = n.GenerateStorageOrder(roothash, segmentInfo, owner, filename, bucketname, filesize)
				if err != nil {
					// verify the space is authorized
					authAcc, err := n.QuaryAuthorizedAccount(owner)
					if err != nil {
						if err.Error() != pattern.ERR_Empty {
							return 0, errors.Wrapf(err, "[QuaryAuthorizedAccount]")
						}
					}
					if n.GetSignatureAcc() != authAcc {
						baseDir := filepath.Dir(segmentInfo[0].SegmentHash)
						os.RemoveAll(baseDir)
						n.DeleteTrackFile(roothash)
						n.Delete([]byte("transfer:" + roothash))
						return 0, errors.New("user deauthorization")
					}
					return 0, errors.Wrapf(err, "[GenerateStorageOrder]")
				}
			}
			time.Sleep(pattern.BlockInterval)
			continue
		}
		break
	}
	if err != nil {
		return 0, errors.Wrapf(err, "[QueryStorageOrder]")
	}

	// store fragment to storage
	err = n.storageData(roothash, segmentInfo, storageOrder.AssignedMiner)
	if err != nil {
		return 0, errors.Wrapf(err, "[storageData]")
	}
	return uint8(storageOrder.Count), nil
}

func (n *Node) storageData(roothash string, segment []pattern.SegmentDataInfo, minerTaskList []pattern.MinerTaskList) error {
	var err error
	var fpath string
	var failed bool
	// query all assigned miner multiaddr
	peerids, accs, err := n.QueryAssignedMiner(minerTaskList)
	if err != nil {
		return errors.Wrapf(err, "[%s] [QueryAssignedMiner]", roothash)
	}

	basedir := filepath.Dir(segment[0].FragmentHash[0])
	for i := 0; i < len(peerids); i++ {
		addr, ok := n.GetPeer(peerids[i])
		if !ok {
			addr, err = n.DHTFindPeer(peerids[i])
			if err != nil {
				failed = true
				n.Track("err", fmt.Sprintf("[%s] No assigned miner found: [%s] [%s]", roothash, accs[i], peerids[i]))
				continue
			}
		}

		err = n.Connect(n.GetCtxQueryFromCtxCancel(), addr)
		if err != nil {
			failed = true
			n.Track("err", fmt.Sprintf("[%s] Connect to miner [%s] failed: [%s]", roothash, accs[i], err))
			continue
		}

		for j := 0; j < len(minerTaskList[i].Hash); j++ {
			fpath = filepath.Join(basedir, string(minerTaskList[i].Hash[j][:]))
			_, err = os.Stat(fpath)
			if err != nil {
				err = utils.CopyFile(filepath.Join(basedir, roothash), filepath.Join(n.GetDirs().FileDir, roothash))
				if err != nil {
					failed = true
					return errors.Wrapf(err, "[CopyFile]")
				}
				_, _, err = n.ProcessingData(filepath.Join(basedir, roothash))
				if err != nil {
					failed = true
					return errors.Wrapf(err, "[ProcessingData]")
				}
			}
			err = n.WriteFileAction(addr.ID, roothash, fpath)
			if err != nil {
				failed = true
				n.Track("err", fmt.Sprintf("[%s] [WriteFileAction] [%s] [%s] err: %v", roothash, accs[i], peerids[i], err))
				break
			}
			n.Track("info", fmt.Sprintf("[%s] [%s] transfer to [%s] ", roothash, string(minerTaskList[i].Hash[j][:]), accs[i]))
		}
	}
	if failed {
		return errors.New("File storage failure")
	}
	return nil
}

func (n *Node) QueryAssignedMiner(minerTaskList []pattern.MinerTaskList) ([]string, []string, error) {
	var peerids = make([]string, len(minerTaskList))
	var accs = make([]string, len(minerTaskList))
	for i := 0; i < len(minerTaskList); i++ {
		minerInfo, err := n.QueryStorageMiner(minerTaskList[i].Account[:])
		if err != nil {
			return peerids, accs, err
		}
		peerids[i] = base58.Encode([]byte(string(minerInfo.PeerId[:])))
		accs[i], _ = sutils.EncodePublicKeyAsCessAccount(minerTaskList[i].Account[:])
	}
	return peerids, accs, nil
}
