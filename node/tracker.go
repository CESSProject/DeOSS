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

const MaxTrackThread = 50

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
	var trackFiles []string

	for {
		trackFiles, err = n.ListTrackFiles()
		if err != nil {
			n.Track("err", err.Error())
			time.Sleep(pattern.BlockInterval)
			continue
		} else if len(trackFiles) == 0 {
			time.Sleep(time.Minute)
			continue
		}

		for _, v := range trackFiles {
			if n.processFileNum() <= MaxTrackThread {
				if !n.contains(v) {
					n.addProcessFile(v)
					go n.trackFileThread(v)
				}
			}
		}
	}
}

func (n *Node) processFileNum() int {
	n.processingFileLock.RLock()
	defer n.processingFileLock.RUnlock()
	return len(n.processingFiles)
}

func (n *Node) contains(str string) bool {
	n.processingFileLock.RLock()
	defer n.processingFileLock.RUnlock()
	for _, v := range n.processingFiles {
		if v == str {
			return true
		}
	}
	return false
}

func (n *Node) addProcessFile(str string) {
	n.processingFileLock.Lock()
	defer n.processingFileLock.Unlock()
	n.processingFiles = append(n.processingFiles, str)
}

func (n *Node) removeProcessFile(r string) {
	n.processingFileLock.Lock()
	defer n.processingFileLock.Unlock()
	for i, v := range n.processingFiles {
		if v == r {
			n.processingFiles = append(n.processingFiles[:i], n.processingFiles[i+1:]...)
		}
	}
}

func (n *Node) trackFileThread(trackFile string) {
	err := n.trackFile(trackFile)
	if err != nil {
		n.Track("err", err.Error())
	}
	n.removeProcessFile(trackFile)
}

func (n *Node) trackFile(trackfile string) error {
	var (
		err          error
		roothash     string
		recordFile   RecordInfo
		storageOrder pattern.StorageOrder
	)
	roothash = filepath.Base(trackfile)
	for {
		recordFile, err = n.ParseTrackFile(roothash)
		if err != nil {
			return errors.Wrapf(err, "[ParseTrackFromFile]")
		}

		_, err = n.QueryFileMetadata(roothash)
		if err != nil {
			if err.Error() != pattern.ERR_Empty {
				time.Sleep(time.Second * pattern.BlockInterval)
				return errors.Wrapf(err, "[%s] [QueryFileMetadata]", roothash)
			}
		} else {
			n.Track("info", fmt.Sprintf("[%s] storage successful", roothash))
			if len(recordFile.SegmentInfo) > 0 {
				baseDir := filepath.Dir(recordFile.SegmentInfo[0].SegmentHash)
				os.Rename(filepath.Join(baseDir, roothash), filepath.Join(n.GetDirs().FileDir, roothash))
				os.RemoveAll(baseDir)
			}
			n.DeleteTrackFile(roothash)
			return nil
		}

		storageOrder, err = n.QueryStorageOrder(roothash)
		if err != nil {
			if err.Error() != pattern.ERR_Empty {
				return errors.Wrapf(err, "[%s] [QueryStorageOrder]", roothash)
			}
			recordFile.Putflag = false
			recordFile.Count = 0
			b, err := json.Marshal(&recordFile)
			if err != nil {
				return errors.Wrapf(err, "[%s] [json.Marshal]", roothash)
			}
			err = n.WriteTrackFile(roothash, b)
			if err != nil {
				return errors.Wrapf(err, "[%s] [WriteTrackFile]", roothash)
			}

			// verify the space is authorized
			authAccs, err := n.QuaryAuthorizedAccounts(recordFile.Owner)
			if err != nil {
				if err.Error() != pattern.ERR_Empty {
					return errors.Wrapf(err, "[%s] [QuaryAuthorizedAccount]", roothash)
				}
			}
			var flag bool
			for _, v := range authAccs {
				if n.GetSignatureAcc() == v {
					flag = true
					break
				}
			}
			if !flag {
				if len(recordFile.SegmentInfo) > 0 {
					baseDir := filepath.Dir(recordFile.SegmentInfo[0].SegmentHash)
					os.RemoveAll(baseDir)
				}
				n.DeleteTrackFile(roothash)
				user, _ := sutils.EncodePublicKeyAsCessAccount(recordFile.Owner)
				return errors.Errorf("[%s] user [%s] deauthorization", roothash, user)
			}

			_, err = n.GenerateStorageOrder(
				roothash,
				recordFile.SegmentInfo,
				recordFile.Owner,
				recordFile.Filename,
				recordFile.Buckname,
				recordFile.Filesize,
			)
			if err != nil {
				return errors.Wrapf(err, "[%s] [GenerateStorageOrder]", roothash)
			}
			time.Sleep(pattern.BlockInterval)
			storageOrder, err = n.QueryStorageOrder(roothash)
			if err != nil {
				return errors.Wrapf(err, "[%s] [QueryStorageOrder]", roothash)
			}
		}

		if roothash != recordFile.Roothash {
			n.DeleteTrackFile(roothash)
			return errors.Errorf("[%s] Recorded filehash [%s] error", roothash, recordFile.Roothash)
		}

		// if recordFile.Putflag {
		// 	if storageorder.AssignedMiner != nil {
		// 		if uint8(storageorder.Count) == recordFile.Count {
		// 			return nil
		// 		}
		// 	}
		// }

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
			storageOrder, err = n.QueryStorageOrder(recordFile.Roothash)
			if err != nil {
				if err.Error() != pattern.ERR_Empty {
					return errors.Wrapf(err, "[%s] [QueryStorageOrder]", roothash)
				}
				n.Track("info", fmt.Sprintf("[%s] Duplicate file become primary file", roothash))
				recordFile.Duplicate = false
				recordFile.Putflag = false
				b, err := json.Marshal(&recordFile)
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

		if recordFile.SegmentInfo == nil {
			resegmentInfo, reHash, err := n.ShardedEncryptionProcessing(filepath.Join(n.GetDirs().FileDir, roothash), "")
			if err != nil {
				return errors.Wrapf(err, "[ShardedEncryptionProcessing]")
			}
			if reHash != reHash {
				return errors.Wrapf(err, "The re-stored file hash is not consistent, please store it separately and specify the original encryption key.")
			}
			recordFile.SegmentInfo = resegmentInfo
		}

		n.storageData(recordFile.Roothash, recordFile.SegmentInfo, storageOrder.CompleteInfo)
		time.Sleep(time.Minute * 2)
	}
}

func (n *Node) storageData(roothash string, segment []pattern.SegmentDataInfo, completeList []pattern.CompleteInfo) error {
	var err error
	var failed bool
	var completed bool
	var dataGroup = make(map[uint8][]string, len(segment[0].FragmentHash))
	for index := 0; index < len(segment[0].FragmentHash); index++ {
		dataGroup[uint8(index+1)] = make([]string, 0)
		for i := 0; i < len(segment); i++ {
			for j := 0; j < len(segment[i].FragmentHash); j++ {
				if index == j {
					dataGroup[uint8(index+1)] = append(dataGroup[uint8(index+1)], string(segment[i].FragmentHash[j]))
					break
				}
			}
		}
	}

	allpeers := n.GetAllStoragePeerId()

	//n.Track("info", fmt.Sprintf("All storage peers: %v", allpeers))
	var sucPeer = make(map[string]struct{}, pattern.DataShards+pattern.ParShards)

	for _, value := range completeList {
		minfo, err := n.QueryStorageMiner(value.Miner[:])
		if err != nil {
			continue
		}
		sucPeer[base58.Encode([]byte(string(minfo.PeerId[:])))] = struct{}{}
	}

	for index, v := range dataGroup {
		completed = false
		for _, value := range completeList {
			if uint8(value.Index) == index {
				completed = true
				n.Track("info", fmt.Sprintf("The %d batch fragments already report", index))
				break
			}
		}

		if completed {
			continue
		}

		n.Track("info", fmt.Sprintf("[%s] Prepare to store the %d batch of fragments", roothash, index))
		n.Track("info", fmt.Sprintf("[%s] The %d batch of fragments: %v", roothash, index, v))
		utils.RandSlice(allpeers)
		for i := 0; i < len(allpeers); i++ {
			failed = false
			if _, ok := sucPeer[allpeers[i]]; ok {
				continue
			}

			t, ok := n.HasBlacklist(allpeers[i])
			if ok {
				if time.Since(time.Unix(t, 0)).Hours() >= 1 {
					n.DelFromBlacklist(allpeers[i])
				}
				continue
			}

			addr, ok := n.GetPeer(allpeers[i])
			if !ok {
				continue
			}

			err = n.Connect(n.GetCtxQueryFromCtxCancel(), addr)
			if err != nil {
				n.AddToBlacklist(allpeers[i])
				continue
			}

			n.Track("info", fmt.Sprintf("[%s] Will transfer to %s", roothash, allpeers[i]))
			for j := 0; j < len(v); j++ {
				err = n.WriteFileAction(addr.ID, roothash, v[j])
				if err != nil {
					failed = true
					n.AddToBlacklist(allpeers[i])
					n.Track("err", fmt.Sprintf("[%s] [WriteFileAction] [%s] err: %v", roothash, allpeers[i], err))
					break
				}
			}
			if !failed {
				sucPeer[allpeers[i]] = struct{}{}
				n.Track("info", fmt.Sprintf("[%s] The %d batch of data transfer was successful", roothash, index))
				break
			}
		}
	}

	return nil
}
