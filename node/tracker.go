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
	"time"

	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/process"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
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

type datagroup struct {
	File     []string
	Miner    string
	Peerid   string
	Index    uint8
	Complete bool
}

func (n *Node) storageData(record TrackerInfo, completeList []chain.CompleteInfo) error {
	var err error
	var dataGroup = make(map[uint8]datagroup, (sconfig.DataShards + sconfig.ParShards))
	for index := 0; index < len(record.Segment[0].FragmentHash); index++ {
		var data = datagroup{
			Index: uint8(index),
		}
		data.File = make([]string, len(record.Segment))
		for i := 0; i < len(record.Segment); i++ {
			data.File[i] = string(record.Segment[i].FragmentHash[index])
		}
		dataGroup[uint8(index+1)] = data
	}

	for _, v := range completeList {
		var value datagroup
		value = dataGroup[uint8(v.Index)]
		value.Complete = true
		value.Miner, _ = sutils.EncodePublicKeyAsCessAccount(v.Miner[:])
		if p, ok := n.GetPeerByAccount(value.Miner); ok {
			value.Peerid = p.ID.String()
		}
		dataGroup[uint8(v.Index)] = value
	}

	if len(record.ShuntMiner.Miners) >= (sconfig.DataShards + sconfig.ParShards) {
		return n.shuntAllStorage(record, dataGroup)
	}

	if len(record.ShuntMiner.Miners) > 0 {
		err = n.shuntPartStorage(record, dataGroup)
		if err != nil {
			return err
		}
	}

	if len(record.Points.Coordinate) > 3 {
		return n.rangeStorage(record, dataGroup)
	}

	priorityMiners := n.Config.Shunt.Peerid
	if len(priorityMiners) > 0 {
		n.highPriorityStorage(record, dataGroup)
	}

	sucCount := 0
	for _, v := range dataGroup {
		if v.Complete {
			sucCount++
		}
	}
	if sucCount >= (sconfig.DataShards + sconfig.ParShards) {
		return nil
	}

	return n.lastStorage(record, dataGroup)
}

func (n *Node) shuntAllStorage(record TrackerInfo, dataGroup map[uint8]datagroup) error {
	var err error
	n.Logtrack("info", fmt.Sprintf("[%s] start shunt storage", record.Fid))
	allcompleted := true
	failed := true
	for index, v := range dataGroup {
		if v.Complete {
			continue
		}
		failed = true
		n.Logtrack("info", fmt.Sprintf("[%s] will transfer the %dth(%d) batch of fragments to priority miners", record.Fid, index, len(v.File)))
		for _, acconut := range record.ShuntMiner.Miners {
			addr, ok := n.GetPeerByAccount(acconut)
			if !ok {
				n.Logtrack("err", fmt.Sprintf("[%s] [%s] the miner was not found or the idle space is not sufficient or the miner information is not synchronized", record.Fid, acconut))
				continue
			}

			n.Peerstore().AddAddrs(addr.ID, addr.Addrs, time.Minute)
			n.Logtrack("info", fmt.Sprintf("[%s] will transfer to the miner: %s", record.Fid, addr.ID.String()))
			for j := 0; j < len(v.File); j++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				err = n.WriteDataAction(ctx, addr.ID, v.File[j], record.Fid, filepath.Base(v.File[j]))
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
				var value datagroup
				value = dataGroup[index]
				value.Complete = true
				value.Miner = acconut
				value.Peerid = addr.ID.String()
				dataGroup[index] = value
				n.Feedback(addr.ID.String(), true)
				n.Logtrack("info", fmt.Sprintf("[%s] %dth batch of all fragments is transferred to %s", record.Fid, index, addr.ID.String()))
				break
			}
			allcompleted = false
		}
	}
	if !allcompleted {
		return fmt.Errorf("shunt storage failed")
	}
	return nil
}

func (n *Node) shuntPartStorage(record TrackerInfo, dataGroup map[uint8]datagroup) error {
	var err error
	n.Logtrack("info", fmt.Sprintf("[%s] start shunt part storage...", record.Fid))
	allcompleted := true
	failed := true

	for _, acconut := range record.ShuntMiner.Miners {
		n.Logtrack("info", fmt.Sprintf("[%s] shunt part: use the miner: %s", record.Fid, acconut))
		addr, ok := n.GetPeerByAccount(acconut)
		if !ok {
			n.Logtrack("err", fmt.Sprintf("[%s] shunt part: the miner was not found or the idle space is not sufficient or not synchronized", record.Fid))
			continue
		}

		failed = true
		for index, v := range dataGroup {
			if v.Complete {
				continue
			}
			n.Peerstore().AddAddrs(addr.ID, addr.Addrs, time.Minute)
			for j := 0; j < len(v.File); j++ {
				n.Logtrack("info", fmt.Sprintf("[%s] shunt part: will transfer the %dth(%d-%d) batch of fragments to the miner: %s", record.Fid, index, len(v.File), j, addr.ID.String()))
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				err = n.WriteDataAction(ctx, addr.ID, v.File[j], record.Fid, filepath.Base(v.File[j]))
				if err != nil {
					failed = true
					n.Logtrack("err", fmt.Sprintf("[%s] shunt part: transfer failed: %v", record.Fid, err))
					n.Feedback(addr.ID.String(), false)
					break
				}
				n.Logtrack("info", fmt.Sprintf("[%s] shunt part: transfer successful", record.Fid))
				failed = false
			}
			n.Peerstore().ClearAddrs(addr.ID)
			if !failed {
				var value datagroup
				value = dataGroup[index]
				value.Complete = true
				value.Miner = acconut
				value.Peerid = addr.ID.String()
				dataGroup[index] = value
				n.Feedback(addr.ID.String(), true)
				n.Logtrack("info", fmt.Sprintf("[%s] shunt part: %dth batch fragments all transferred to: %s %s", record.Fid, index, acconut, addr.ID.String()))
				break
			}
			allcompleted = false
		}
		if !allcompleted {
			return fmt.Errorf("shunt part storage failed")
		}
	}
	return nil
}

func (n *Node) rangeStorage(record TrackerInfo, dataGroup map[uint8]datagroup) error {
	var err error

	n.Logtrack("info", fmt.Sprintf("[%s] start range storage", record.Fid))

	itor, err := n.NewPeersIterator(sconfig.DataShards + sconfig.ParShards)
	if err != nil {
		return err
	}
	allcompleted := true
	failed := true
	for index, v := range dataGroup {
		if v.Complete {
			continue
		}
		n.Logtrack("info", fmt.Sprintf("[%s] will transfer the %dth(%d) batch of fragments", record.Fid, index, len(v.File)))
		failed = true
		for peer, ok := itor.GetPeer(); ok; peer, ok = itor.GetPeer() {
			n.Logtrack("info", fmt.Sprintf("[%s] will transfer to the range miner: %s", record.Fid, peer.ID.String()))
			coordinateInfo, err := n.getAddrsCoordinate(peer.Addrs)
			if err != nil {
				n.Logtrack("err", fmt.Sprintf("[%s] getAddrsCoordinate: %v", record.Fid, err))
				continue
			}
			if !coordinate.PointInRange(coordinateInfo, record.Points) {
				n.Logtrack("err", fmt.Sprintf("[%s] %v not in range: %v", record.Fid, coordinateInfo, record.Points))
				continue
			}

			n.Peerstore().AddAddrs(peer.ID, peer.Addrs, time.Minute)
			for j := 0; j < len(v.File); j++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				err = n.WriteDataAction(ctx, peer.ID, v.File[j], record.Fid, filepath.Base(v.File[j]))
				if err != nil {
					failed = true
					n.Logtrack("err", fmt.Sprintf("[%s] transfer to %s failed: %v", record.Fid, peer.ID.String(), err))
					n.Feedback(peer.ID.String(), false)
					break
				}
				n.Logtrack("info", fmt.Sprintf("[%s] The %dth fragment of the %dth batch is transferred to %s", record.Fid, j, index, peer.ID.String()))
				failed = false
			}
			n.Peerstore().ClearAddrs(peer.ID)
			if !failed {
				var value datagroup
				value = dataGroup[index]
				value.Complete = true
				value.Peerid = peer.ID.String()
				dataGroup[index] = value
				n.Feedback(peer.ID.String(), true)
				n.Logtrack("info", fmt.Sprintf("[%s] %dth batch of all fragments is transferred to %s", record.Fid, index, peer.ID.String()))
				break
			}
			allcompleted = false
		}
	}
	if !allcompleted {
		return fmt.Errorf("range storage failed")
	}
	return nil
}

func (n *Node) highPriorityStorage(record TrackerInfo, dataGroup map[uint8]datagroup) error {
	var err error
	priorityPeers := n.Config.Shunt.Peerid
	if len(priorityPeers) <= 0 {
		return nil
	}

	var sucPeer = make(map[string]struct{}, 0)

	for index, v := range dataGroup {
		if v.Complete {
			sucPeer[v.Peerid] = struct{}{}
			continue
		}
		failed := true
		n.Logtrack("info", fmt.Sprintf("[%s] will transfer the %dth(%d) batch of fragments to high priority miners", record.Fid, index, len(v.File)))
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
			n.Logtrack("info", fmt.Sprintf("[%s] will transfer to the miner: %s", record.Fid, peerid))
			for j := 0; j < len(v.File); j++ {
				n.Logtrack("info", fmt.Sprintf("[%s] will transfer fragment: %s", record.Fid, v.File[j]))
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				err = n.WriteDataAction(ctx, addrs.ID, v.File[j], record.Fid, filepath.Base(v.File[j]))
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
				var value datagroup
				value = dataGroup[index]
				value.Complete = true
				value.Peerid = peerid
				dataGroup[index] = value
				n.Feedback(peerid, true)
				n.Logtrack("info", fmt.Sprintf("[%s] %dth batch of all fragments is transferred to %s", record.Fid, index, peerid))
				break
			}
		}
	}

	return err
}

func (n *Node) lastStorage(record TrackerInfo, dataGroup map[uint8]datagroup) error {
	// allpeers := n.GetAllStoragePeerId()
	itor, err := n.NewPeersIterator(sconfig.DataShards + sconfig.ParShards)
	if err != nil {
		return err
	}
	failed := true
	var sucPeer = make(map[string]struct{}, 0)
	for index, v := range dataGroup {
		if v.Complete {
			sucPeer[v.Peerid] = struct{}{}
			continue
		}
		failed = true
		for peer, ok := itor.GetPeer(); ok; peer, ok = itor.GetPeer() {
			if _, ok := sucPeer[peer.ID.String()]; ok {
				continue
			}
			n.Logtrack("info", fmt.Sprintf("[%s] last storage: use peer: %s", record.Fid, peer.ID.String()))
			n.Peerstore().AddAddrs(peer.ID, peer.Addrs, time.Minute)
			for j := 0; j < len(v.File); j++ {
				n.Logtrack("info", fmt.Sprintf("[%s] last storage: will transfer the %dth(%d-%d) batch of fragments", record.Fid, index, len(v.File), j))
				n.Logtrack("info", fmt.Sprintf("[%s] last storage: will transfer fragment: %s", record.Fid, v.File[j]))
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				err = n.WriteDataAction(ctx, peer.ID, v.File[j], record.Fid, filepath.Base(v.File[j]))
				if err != nil {
					failed = true
					n.Logtrack("info", fmt.Sprintf("[%s] last storage: transfer failed: %v", record.Fid, err))
					break
				}
				failed = false
				n.Logtrack("info", fmt.Sprintf("[%s] last storage: transfer successful", record.Fid))
			}
			n.Peerstore().ClearAddrs(peer.ID)
			if !failed {
				sucPeer[peer.ID.String()] = struct{}{}
				var value datagroup
				value = dataGroup[index]
				value.Complete = true
				value.Peerid = peer.ID.String()
				dataGroup[index] = value
				n.Feedback(peer.ID.String(), true)
				n.Logtrack("info", fmt.Sprintf("[%s] last storage: the %dth batch of fragments all transferred to: %s", record.Fid, index, peer.ID.String()))
				break
			}
		}
	}
	return err
}
