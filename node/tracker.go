/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
)

// tracker
func (n *Node) Tracker(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Logtrack("info", ">>>>> start tracker <<<<<")

	var err error
	var processNum int
	var trackFiles []string

	for {
		trackFiles, err = n.ListTrackFiles()
		if err != nil {
			n.Logtrack("err", err.Error())
			time.Sleep(chain.BlockInterval)
			continue
		}
		if len(trackFiles) == 0 {
			time.Sleep(time.Minute)
			continue
		}
		processNum = n.GetTrackFileNum()

		if processNum < configs.MaxTrackThread {
			for _, v := range trackFiles {
				if _, err = os.Stat(v); err != nil {
					continue
				}
				err = n.AddTrackFile(filepath.Base(v))
				if err != nil {
					continue
				}
				n.Logtrack("info", fmt.Sprintf("start track file: %s", filepath.Base(v)))
				go func(file string) { n.trackFileThread(file) }(v)
				time.Sleep(chain.BlockInterval)
			}
		}
		time.Sleep(time.Minute)
	}
}

func (n *Node) trackFileThread(trackFile string) {
	defer func() {
		n.DelTrackFile(filepath.Base(trackFile))
	}()
	err := n.trackFile(trackFile)
	if err != nil {
		n.Logtrack("err", err.Error())
	}
	n.Logtrack("info", fmt.Sprintf("end track file: %s", filepath.Base(trackFile)))
}

func (n *Node) trackFile(trackfile string) error {
	var (
		err          error
		roothash     string
		recordFile   TrackerInfo
		storageOrder chain.StorageOrder
	)
	roothash = filepath.Base(trackfile)
	recordFile, err = n.ParseTrackFile(roothash)
	if err != nil {
		return errors.Wrapf(err, "[ParseTrackFromFile]")
	}

	for {
		_, err = n.QueryFile(roothash, -1)
		if err != nil {
			if err.Error() != chain.ERR_Empty {
				time.Sleep(time.Second * chain.BlockInterval)
				return errors.Wrapf(err, "[%s] [QueryFile]", roothash)
			}
		} else {
			n.Logtrack("info", fmt.Sprintf("[%s] storage successful", roothash))
			os.RemoveAll(recordFile.CacheDir)
			n.DeleteTrackFile(roothash) // if storage successfully ,remove track file
			return nil
		}

		storageOrder, err = n.QueryDealMap(roothash, -1)
		if err != nil {
			if err.Error() != chain.ERR_Empty {
				return errors.Wrapf(err, "[%s] [QueryStorageOrder]", roothash)
			}
			recordFile.PutFlag = false
			b, err := json.Marshal(&recordFile)
			if err != nil {
				return errors.Wrapf(err, "[%s] [json.Marshal]", roothash)
			}
			err = n.WriteTrackFile(roothash, b)
			if err != nil {
				return errors.Wrapf(err, "[%s] [WriteTrackFile]", roothash)
			}

			// verify the space is authorized
			authAccs, err := n.QueryAuthorityList(recordFile.Owner, -1)
			if err != nil {
				if err.Error() != chain.ERR_Empty {
					return errors.Wrapf(err, "[%s] [QuaryAuthorizedAccount]", roothash)
				}
			}
			var flag bool
			for _, v := range authAccs {
				if sutils.CompareSlice(n.GetSignatureAccPulickey(), v[:]) {
					flag = true
					break
				}
			}
			if !flag {
				os.RemoveAll(recordFile.CacheDir)
				n.DeleteTrackFile(roothash)
				user, _ := sutils.EncodePublicKeyAsCessAccount(recordFile.Owner)
				return errors.Errorf("[%s] user [%s] deauthorization", roothash, user)
			}

			txhash, err := n.PlaceStorageOrder(
				roothash,
				recordFile.FileName,
				recordFile.BucketName,
				recordFile.TerritoryName,
				recordFile.Segment,
				recordFile.Owner,
				recordFile.FileSize,
			)
			if err != nil {
				return errors.Wrapf(err, "[%s] [%s] [GenerateStorageOrder]", txhash, roothash)
			}
			n.Logtrack("info", fmt.Sprintf("[%s] GenerateStorageOrder: %s", roothash, txhash))
			time.Sleep(chain.BlockInterval * 3)
			storageOrder, err = n.QueryDealMap(roothash, -1)
			if err != nil {
				return errors.Wrapf(err, "[%s] [QueryStorageOrder]", roothash)
			}
		}

		if roothash != recordFile.Fid {
			n.Logtrack("info", fmt.Sprintf("[%s] invalid track file: %s", roothash, recordFile.Fid))
			return errors.Errorf("[%s] Recorded filehash [%s] error", roothash, recordFile.Fid)
		}

		if recordFile.Segment == nil {
			resegmentInfo, reHash, err := process.FullProcessing(filepath.Join(n.fileDir, roothash), recordFile.Cipher, recordFile.CacheDir)
			if err != nil {
				resegmentInfo, reHash, err = process.FullProcessing(filepath.Join(n.GetBasespace(), configs.FILE_CACHE, roothash), recordFile.Cipher, recordFile.CacheDir)
				if err != nil {
					return errors.Wrapf(err, "[FullProcessing]")
				}
			}
			if reHash != roothash {
				return errors.Wrapf(err, "The re-stored file hash is not consistent, please store it separately and specify the original encryption key.")
			}
			recordFile.Segment = resegmentInfo
		}

		err = n.storageData(recordFile, storageOrder.CompleteList)
		n.FlushlistedPeerNodes(5*time.Second, n.GetDHTable()) //refresh the user-configured storage node list
		if err != nil {
			n.Logtrack("err", err.Error())
			return err
		}
		n.Logtrack("info", fmt.Sprintf("[%s] file transfer completed", roothash))
		time.Sleep(time.Minute * 3)
	}
}

func (n *Node) storageData(record TrackerInfo, completeList []chain.CompleteInfo) error {
	var err error
	var failed bool
	var completed bool
	var dataGroup = make(map[uint8][]string, (sconfig.DataShards + sconfig.ParShards))
	for index := 0; index < len(record.Segment[0].FragmentHash); index++ {
		for i := 0; i < len(record.Segment); i++ {
			dataGroup[uint8(index+1)] = append(dataGroup[uint8(index+1)], string(record.Segment[i].FragmentHash[index]))
		}
	}

	var sucPeer = make(map[string]struct{}, sconfig.DataShards+sconfig.ParShards)

	for _, value := range completeList {
		minfo, err := n.QueryMinerItems(value.Miner[:], -1)
		if err != nil {
			continue
		}
		sucPeer[base58.Encode([]byte(string(minfo.PeerId[:])))] = struct{}{}
	}

	if len(record.ShuntMiner.Miners) > 0 {
		return n.shuntStorage(record, completeList, dataGroup)
	}

	if len(record.Points.Coordinate) > 0 {
		return n.rangeStorage(record, completeList, dataGroup, sucPeer)
	}

	priorityMiners := n.Config.Shunt.Peerid
	if len(priorityMiners) > 0 {
		n.highPriorityStorage(record, completeList, dataGroup, sucPeer)
	}

	// allpeers := n.GetAllStoragePeerId()
	itor, err := n.NewPeersIterator(sconfig.DataShards + sconfig.ParShards)
	if err != nil {
		return err
	}

	for index, v := range dataGroup {
		completed = false
		for _, value := range completeList {
			if uint8(value.Index) == index {
				completed = true
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth batch fragments already report", record.Fid, index))
				break
			}
		}

		if completed {
			continue
		}

		n.Logtrack("info", fmt.Sprintf("[%s] will transfer the %dth(%d) batch of fragments", record.Fid, index, len(v)))
		//utils.RandSlice(allpeers)
		for peer, ok := itor.GetPeer(); ok; peer, ok = itor.GetPeer() {
			failed = true
			if _, ok := sucPeer[peer.ID.String()]; ok {
				continue
			}

			n.Peerstore().AddAddrs(peer.ID, peer.Addrs, time.Minute)
			n.Logtrack("info", fmt.Sprintf("[%s] Will transfer to %s", record.Fid, peer.ID.String()))
			for j := 0; j < len(v); j++ {
				for k := 0; k < 3; k++ {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					err = n.WriteDataAction(ctx, peer.ID, v[j], record.Fid, filepath.Base(v[j]))
					if err != nil {
						failed = true
						if strings.Contains(err.Error(), "connection refused") {
							break
						}
						time.Sleep(chain.BlockInterval * 3)
						continue
					}
					failed = false
					break
				}
				if failed {
					n.Logtrack("err", fmt.Sprintf("[%s] transfer to %s failed: %v", record.Fid, peer.ID.String(), err))
					n.Feedback(peer.ID.String(), false)
					break
				}
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth fragment of the %dth batch is transferred to %s", record.Fid, j, index, peer.ID.String()))
			}
			n.Peerstore().ClearAddrs(peer.ID)
			if !failed {
				sucPeer[peer.ID.String()] = struct{}{}
				n.Feedback(peer.ID.String(), true)
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth batch of fragments is transferred to %s", record.Fid, index, peer.ID.String()))
				break
			}
		}
	}

	return nil
}

func (n *Node) shuntStorage(record TrackerInfo, completeList []chain.CompleteInfo, dataGroup map[uint8][]string) error {
	var err error
	n.Logtrack("info", fmt.Sprintf("[%s] start shunt storage", record.Fid))
	var sucPeer = make(map[string]struct{}, sconfig.DataShards+sconfig.ParShards)
	for _, value := range completeList {
		minfo, err := n.QueryMinerItems(value.Miner[:], -1)
		if err != nil {
			continue
		}
		sucPeer[base58.Encode([]byte(string(minfo.PeerId[:])))] = struct{}{}
	}
	completed := false
	for index, v := range dataGroup {
		completed = false
		for _, value := range completeList {
			if uint8(value.Index) == index {
				completed = true
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth batch fragments already report", record.Fid, index))
				break
			}
		}
		if completed {
			continue
		}

		n.Logtrack("info", fmt.Sprintf("[%s] will transfer the %dth(%d) batch of fragments to priority miners", record.Fid, index, len(v)))
		for _, acconut := range record.ShuntMiner.Miners {
			addr, ok := n.GetPeerByAccount(acconut)
			if !ok {
				n.Logtrack("err", fmt.Sprintf("[%s] [%s] the miner was not found or the idle space is not sufficient or the miner information is not synchronized", record.Fid, acconut))
				continue
			}

			n.Peerstore().AddAddrs(addr.ID, addr.Addrs, time.Minute)
			failed := true
			n.Logtrack("info", fmt.Sprintf("[%s] will transfer to the miner: %s", record.Fid, addr.ID.String()))
			for j := 0; j < len(v); j++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				err = n.WriteDataAction(ctx, addr.ID, v[j], record.Fid, filepath.Base(v[j]))
				if err != nil {
					failed = true
					n.Logtrack("err", fmt.Sprintf("[%s] transfer to %s failed: %v", record.Fid, addr.ID.String(), err))
					n.Feedback(addr.ID.String(), false)
					break
				}
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth fragment of the %dth batch is transferred to %s", record.Fid, j, index, addr.ID.String()))
				failed = false
			}
			n.Peerstore().ClearAddrs(addr.ID)
			if !failed {
				sucPeer[addr.ID.String()] = struct{}{}
				n.Feedback(addr.ID.String(), true)
				n.Logtrack("info", fmt.Sprintf("[%s] %dth batch of all fragments is transferred to %s", record.Fid, index, addr.ID.String()))
				break
			}
		}
	}
	return err
}

func (n *Node) rangeStorage(record TrackerInfo, completeList []chain.CompleteInfo, dataGroup map[uint8][]string, sucPeer map[string]struct{}) error {
	var err error
	n.Logtrack("info", fmt.Sprintf("[%s] start range storage", record.Fid))

	completed := false
	// allpeers := n.GetAllStoragePeerId()
	itor, err := n.NewPeersIterator(sconfig.DataShards + sconfig.ParShards)
	if err != nil {
		return err
	}

	for index, v := range dataGroup {
		completed = false
		for _, value := range completeList {
			if uint8(value.Index) == index {
				completed = true
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth batch fragments already report", record.Fid, index))
				break
			}
		}

		if completed {
			continue
		}

		n.Logtrack("info", fmt.Sprintf("[%s] will transfer the %dth(%d) batch of fragments", record.Fid, index, len(v)))
		//utils.RandSlice(allpeers)
		failed := true
		for peer, ok := itor.GetPeer(); ok; peer, ok = itor.GetPeer() {
			failed = true
			if _, ok := sucPeer[peer.ID.String()]; ok {
				continue
			}

			n.Peerstore().AddAddrs(peer.ID, peer.Addrs, time.Minute)
			n.Logtrack("info", fmt.Sprintf("[%s] Will transfer to %s", record.Fid, peer.ID.String()))
			for j := 0; j < len(v); j++ {
				for k := 0; k < 3; k++ {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					err = n.WriteDataAction(ctx, peer.ID, v[j], record.Fid, filepath.Base(v[j]))
					if err != nil {
						time.Sleep(chain.BlockInterval * 3)
						continue
					}
					failed = false
					break
				}
				if failed {
					n.Logtrack("err", fmt.Sprintf("[%s] transfer to %s failed: %v", record.Fid, peer.ID.String(), err))
					n.Feedback(peer.ID.String(), false)
					break
				}
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth fragment of the %dth batch is transferred to %s", record.Fid, j, index, peer.ID.String()))
			}
			n.Peerstore().ClearAddrs(peer.ID)
			if !failed {
				sucPeer[peer.ID.String()] = struct{}{}
				n.Feedback(peer.ID.String(), true)
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth batch of fragments is transferred to %s", record.Fid, index, peer.ID.String()))
				break
			}
		}

	}

	return err
}

func (n *Node) highPriorityStorage(record TrackerInfo, completeList []chain.CompleteInfo, dataGroup map[uint8][]string, sucPeer map[string]struct{}) error {
	var err error
	priorityPeers := n.Config.Shunt.Peerid
	if len(priorityPeers) > 0 {
		completed := false
		for index, v := range dataGroup {
			completed = false
			for _, value := range completeList {
				if uint8(value.Index) == index {
					completed = true
					n.Logtrack("info", fmt.Sprintf("[%s] The %dth batch fragments already report", record.Fid, index))
					break
				}
			}
			if completed {
				continue
			}

			n.Logtrack("info", fmt.Sprintf("[%s] will transfer the %dth(%d) batch of fragments to priority miners", record.Fid, index, len(v)))
			for _, peerid := range priorityPeers {
				if _, ok := sucPeer[peerid]; ok {
					continue
				}

				addrs, ok := n.GetPeer(peerid)
				if !ok {
					n.Logtrack("info", fmt.Sprintf("[%s] not found this peer: %s", record.Fid, peerid))
					continue
				}

				n.Peerstore().AddAddrs(addrs.ID, addrs.Addrs, time.Minute)
				failed := true
				n.Logtrack("info", fmt.Sprintf("[%s] will transfer to the miner: %s", record.Fid, peerid))
				for j := 0; j < len(v); j++ {
					n.Logtrack("info", fmt.Sprintf("[%s] will transfer fragment: %s", record.Fid, v[j]))
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					err = n.WriteDataAction(ctx, addrs.ID, v[j], record.Fid, filepath.Base(v[j]))
					if err != nil {
						failed = true
						n.Logtrack("err", fmt.Sprintf("[%s] transfer to %s failed: %v", record.Fid, peerid, err))
						n.Feedback(peerid, false)
						break
					}
					n.Logtrack("info", fmt.Sprintf("[%s] The %dth fragment of the %dth batch is transferred to %s", record.Fid, j, index, peerid))
					failed = false
				}
				n.Peerstore().ClearAddrs(addrs.ID)
				if !failed {
					sucPeer[peerid] = struct{}{}
					n.Feedback(peerid, true)
					n.Logtrack("info", fmt.Sprintf("[%s] %dth batch of all fragments is transferred to %s", record.Fid, index, peerid))
					break
				}
			}
		}
	}
	return err
}
