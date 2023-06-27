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
	"syscall"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/bytedance/sonic"
	"github.com/libp2p/go-libp2p/core/peer"
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

const MinRecordInfoLength = 132

func (n *Node) tracker(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	var err error
	var recordErr string
	var trackFiles []string

	for {
		trackFiles, err = filepath.Glob(fmt.Sprintf("%s/*", n.TrackDir))
		if err != nil {
			if err.Error() != recordErr {
				n.Upfile("err", recordErr)
				recordErr = err.Error()
			}
			time.Sleep(pattern.BlockInterval)
			continue
		}
		for _, v := range trackFiles {
			err = n.trackFile(v)
		}
	}
}

func (n *Node) trackFile(trackfile string) error {
	var (
		err           error
		count         uint8
		roothash      string
		ownerAcc      string
		files         []string
		b             []byte
		f             *os.File
		recordFile    RecordInfo
		storageorder  pattern.StorageOrder
		linuxFileAttr *syscall.Stat_t
	)

	roothash = filepath.Base(trackfile)
	b, err = n.Get([]byte("transfer:" + roothash))
	if err == nil {
		storageorder, err = n.QueryStorageOrder(roothash)
		if err != nil {
			if err.Error() != pattern.ERR_Empty {
				return errors.Wrapf(err, "[QueryStorageOrder]")
			}

			_, err = n.QueryFileMetadata(roothash)
			if err != nil {
				if err.Error() != pattern.ERR_Empty {
					return errors.Wrapf(err, "[QueryFileMetadata]")
				}
				if err.Error() == pattern.ERR_Empty {
					n.Upfile("info", fmt.Sprintf("[%s] File has been deleted", roothash))
					os.RemoveAll(filepath.Join(n.GetDirs().FileDir, ownerAcc, roothash))
					n.DeleteTrackFile(roothash)
					n.Delete([]byte("transfer:" + roothash))
					return nil
				}
			} else {
				recordFile, err = n.ParseRTrackFromFile(roothash)
				if err == nil {
					ownerAcc, err = utils.EncodePublicKeyAsCessAccount(recordFile.Owner)
					if err == nil {
						os.Rename(filepath.Join(n.GetDirs().FileDir, ownerAcc, roothash, roothash), filepath.Join(n.GetDirs().FileDir, roothash))
						os.RemoveAll(filepath.Join(n.GetDirs().FileDir, ownerAcc, roothash))
						n.DeleteTrackFile(roothash)
						n.Delete([]byte("transfer:" + roothash))
					}
					n.Upfile("info", fmt.Sprintf("[%s] File storage success", roothash))
				}
			}
			return nil
		}
	}

	recordFile, err = n.ParseRTrackFromFile(roothash)
	if err != nil {
		return errors.Wrapf(err, "[ParseRTrackFromFile]")
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
				n.Upfile("err", fmt.Sprintf("[%s] Duplicate file declaration failed: %v", roothash, err))
				return errors.Wrapf(err, " [%s] [GenerateStorageOrder]", roothash)
			}
			ownerAcc, err = utils.EncodePublicKeyAsCessAccount(recordFile.Owner)
			if err == nil {
				os.Rename(filepath.Join(n.GetDirs().FileDir, ownerAcc, roothash, roothash), filepath.Join(n.GetDirs().FileDir, roothash))
				os.RemoveAll(filepath.Join(n.GetDirs().FileDir, ownerAcc, roothash))
			}
			n.DeleteTrackFile(roothash)
			n.Upfile("info", fmt.Sprintf("[%s] Duplicate file declaration suc", roothash))
			return nil
		}
		_, err = n.QueryStorageOrder(recordFile.Roothash)
		if err != nil {
			if err.Error() != pattern.ERR_Empty {
				return errors.Wrapf(err, "[%s] [QueryStorageOrder]", roothash)
			}
			n.Upfile("info", fmt.Sprintf("[%s] Duplicate file become primary file", roothash))
			recordFile.Duplicate = false
			recordFile.Putflag = false
			b, err = sonic.Marshal(&recordFile)
			if err != nil {
				return errors.Wrapf(err, "[sonic.Marshal]")
			}
			err = n.WriteTrackFile(roothash, b)
			if err != nil {
				return errors.Wrapf(err, "[WriteTrackFile]")
			}
		}
		return nil
	}

	count, err = n.backupFiles(recordFile.Owner, recordFile.SegmentInfo, roothash, recordFile.Filename, recordFile.Buckname, recordFile.Filesize)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
		return nil
	}

	n.Upfile("info", fmt.Sprintf("File [%s] backup suc", roothash))

	recordFile.Putflag = true
	recordFile.Count = count
	b, err = json.Marshal(&recordFile)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
		continue
	}

	f, err = os.OpenFile(filepath.Join(n.TrackDir, roothash), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	if err != nil {
		n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
		continue
	}
	_, err = f.Write(b)
	if err != nil {
		f.Close()
		n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
		continue
	}

	err = f.Sync()
	if err != nil {
		f.Close()
		n.Upfile("err", fmt.Sprintf("[%v] %v", roothash, err))
		continue
	}
	f.Close()
	n.Cache.Put([]byte("transfer:"+roothash), []byte(fmt.Sprintf("%v", count)))

	// Delete files that have not been accessed for more than 30 days
	files, _ = filepath.Glob(filepath.Join(n.GetDirs().FileDir, "/*"))
	for _, v := range files {
		fs, err := os.Stat(v)
		if err == nil {
			linuxFileAttr = fs.Sys().(*syscall.Stat_t)
			if time.Since(time.Unix(linuxFileAttr.Atim.Sec, 0)).Hours() > configs.FileCacheExpirationTime {
				os.Remove(v)
			}
		}
	}
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
	// query all assigned miner multiaddr
	peerids, accs, err := n.QueryAssignedMiner(minerTaskList)
	if err != nil {
		return errors.Wrapf(err, "[QueryAssignedMiner]")
	}

	basedir := filepath.Dir(segment[0].FragmentHash[0])
	for i := 0; i < len(peerids); i++ {
		if !n.Has(peerids[i]) {
			return fmt.Errorf("Allocated storage node not found: [%s] [%s]", accs[i], peerids[i])
		}

		id, _ := peer.Decode(peerids[i])

		for j := 0; j < len(minerTaskList[i].Hash); j++ {
			fpath = filepath.Join(basedir, string(minerTaskList[i].Hash[j][:]))
			_, err = os.Stat(fpath)
			if err != nil {
				err = utils.CopyFile(filepath.Join(basedir, roothash), filepath.Join(n.GetDirs().FileDir, roothash))
				if err != nil {
					return errors.Wrapf(err, "[CopyFile]")
				}
				_, _, err = n.ProcessingData(filepath.Join(basedir, roothash))
				if err != nil {
					return errors.Wrapf(err, "[ProcessingData]")
				}
			}
			err = n.WriteFileAction(id, roothash, fpath)
			if err != nil {
				return errors.Wrapf(err, "[WriteFileAction]")
			}
		}
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
