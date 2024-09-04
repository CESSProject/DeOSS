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
	"github.com/CESSProject/cess-go-sdk/chain"
	schain "github.com/CESSProject/cess-go-sdk/chain"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
)

type StorageDataType struct {
	Fid      string
	Complete []string
	Data     [][]string
}

// tracker
func (n *Node) TrackerV2(ch chan<- bool) {
	defer func() {
		ch <- true
		if err := recover(); err != nil {
			n.Pnc(utils.RecoverError(err))
		}
	}()

	n.Logtrack("info", ">>>>> start trackerv2 <<<<<")
	var tNow time.Time
	for {
		tNow = time.Now()
		n.processTrackFiles()
		if time.Since(tNow).Minutes() < 3.0 {
			time.Sleep(time.Minute * 3)
		}
	}
}

func (n *Node) processTrackFiles() {
	var err error
	var count uint8
	var trackFiles []string
	trackFiles, err = n.ListTrackFiles()
	if err != nil {
		n.Logtrack("err", err.Error())
		return
	}
	if len(trackFiles) <= 0 {
		n.Logtrack("info", "no track files")
		return
	}

	n.Logtrack("info", fmt.Sprintf("number of track files: %d", len(trackFiles)))

	count = 0
	fid := ""
	var dealFiles = make([]StorageDataType, 0)
	for i := 0; i < len(trackFiles); i++ {
		fid = filepath.Base(trackFiles[i])
		storageDataType, ok, err := n.checkFileState(fid)
		if err != nil {
			n.Logtrack("err", fmt.Sprintf("checkFileState: %v", err))
			continue
		}
		if ok {
			n.Logtrack("info", fmt.Sprintf(" %s storage suc", fid))
			continue
		}

		dealFiles = append(dealFiles, storageDataType)
		count++
		if count >= 10 {
			n.Logtrack("info", fmt.Sprintf(" will storage %d files: %v", len(dealFiles), dealFiles))
			err = n.storageFiles(dealFiles)
			if err != nil {
				n.Logtrack("err", err.Error())
				return
			}
			count = 0
			dealFiles = make([]StorageDataType, 0)
		}
	}
	if len(dealFiles) > 0 {
		n.Logtrack("info", fmt.Sprintf(" will storage %d files: %v", len(dealFiles), dealFiles))
		err = n.storageFiles(dealFiles)
		if err != nil {
			n.Logtrack("err", err.Error())
		}
	}
}

func (n *Node) checkFileState(fid string) (StorageDataType, bool, error) {
	recordFile, err := n.ParseTrackFile(fid)
	if err != nil {
		return StorageDataType{}, false, fmt.Errorf("[ParseTrackFromFile(%s)] %v", fid, err)
	}

	_, err = n.QueryFile(fid, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			return StorageDataType{}, false, err
		}
	} else {
		for i := 0; i < len(recordFile.Segment); i++ {
			for j := 0; j < len(recordFile.Segment[i].FragmentHash); j++ {
				os.Remove(filepath.Join(recordFile.CacheDir, recordFile.Segment[i].FragmentHash[j]))
			}
		}
		n.DeleteTrackFile(fid)
		return StorageDataType{}, true, nil
	}

	flag := false
	if recordFile.Segment == nil {
		flag = true
	}

	for i := 0; i < len(recordFile.Segment); i++ {
		for j := 0; j < len(recordFile.Segment[i].FragmentHash); j++ {
			_, err = os.Stat(recordFile.Segment[i].FragmentHash[j])
			if err != nil {
				flag = true
				break
			}
		}
		if flag {
			break
		}
	}

	if flag {
		segment, hash, err := n.reFullProcessing(fid, recordFile.Cipher, recordFile.CacheDir)
		if err != nil {
			return StorageDataType{}, false, errors.Wrapf(err, "reFullProcessing")
		}
		if recordFile.Fid != hash {
			return StorageDataType{}, false, fmt.Errorf("The fid after reprocessing is inconsistent [%s != %s] %v", recordFile.Fid, hash, err)
		}
		recordFile.Segment = segment
	}

	var storageDataType = StorageDataType{
		Fid:      fid,
		Complete: make([]string, 0),
		Data:     make([][]string, 0),
	}

	dealmap, err := n.QueryDealMap(fid, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			return StorageDataType{}, false, err
		}
	} else {
		for index := 0; index < (sconfig.DataShards + sconfig.ParShards); index++ {
			acc, ok := IsComplete(index+1, dealmap.CompleteList)
			if ok {
				storageDataType.Complete = append(storageDataType.Complete, acc)
				continue
			}
			var value = make([]string, 0)
			for i := 0; i < len(recordFile.Segment); i++ {
				value = append(value, string(recordFile.Segment[i].FragmentHash[index]))
			}
			storageDataType.Data = append(storageDataType.Data, value)
		}
		return storageDataType, false, nil
	}

	recordFile.PutFlag = false
	b, err := json.Marshal(&recordFile)
	if err != nil {
		return StorageDataType{}, false, errors.Wrapf(err, "[%s] [json.Marshal]", fid)
	}
	err = n.WriteTrackFile(fid, b)
	if err != nil {
		return StorageDataType{}, false, errors.Wrapf(err, "[%s] [WriteTrackFile]", fid)
	}

	// verify the space is authorized
	authAccs, err := n.QueryAuthorityList(recordFile.Owner, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			return StorageDataType{}, false, err
		}
	}

	flag = false
	for _, v := range authAccs {
		if sutils.CompareSlice(n.GetSignatureAccPulickey(), v[:]) {
			flag = true
			break
		}
	}

	if !flag {
		// os.RemoveAll(recordFile.CacheDir)
		// n.DeleteTrackFile(roothash)
		user, _ := sutils.EncodePublicKeyAsCessAccount(recordFile.Owner)
		return StorageDataType{}, true, errors.Errorf("[%s] user [%s] has revoked authorization", fid, user)
	}

	txhash, err := n.PlaceStorageOrder(
		fid,
		recordFile.FileName,
		recordFile.BucketName,
		recordFile.TerritoryName,
		recordFile.Segment,
		recordFile.Owner,
		recordFile.FileSize,
	)
	if err != nil {
		return StorageDataType{}, false, err
	}
	n.Logtrack("info", fmt.Sprintf("[%s] PlaceStorageOrder suc: %s", fid, txhash))

	for index := 0; index < (sconfig.DataShards + sconfig.ParShards); index++ {
		var value = make([]string, 0)
		for i := 0; i < len(recordFile.Segment); i++ {
			value = append(value, string(recordFile.Segment[i].FragmentHash[index]))
		}
		storageDataType.Data = append(storageDataType.Data, value)
	}
	return storageDataType, false, nil
}

func (n *Node) storageFiles(tracks []StorageDataType) error {
	allpeers := n.GetAllWhitelist()
	allpeers = append(allpeers, n.GetAllPeerId()...)
	length := len(allpeers)
	for i := 0; i < length; i++ {
		n.Logtrack("info", fmt.Sprintf(" will use peer: %s", allpeers[i]))
		if n.IsInBlacklist(allpeers[i]) {
			n.Logtrack("info", fmt.Sprintf(" %s peer in blacklist", allpeers[i]))
			continue
		}
		err := n.storageToPeer(allpeers[i], tracks)
		if err != nil {
			n.Logtrack("err", err.Error())
		}
	}
	return nil
}

func (n *Node) storageToPeer(peerid string, tracks []StorageDataType) error {
	addr, ok := n.GetPeer(peerid)
	if !ok {
		n.Logtrack("err", fmt.Sprintf(" %s peer not found", peerid))
		return fmt.Errorf("%s not found addr", peerid)
	}

	n.Peerstore().AddAddrs(addr.ID, addr.Addrs, time.Hour)
	err := n.storagedata(addr.ID, tracks)
	n.Peerstore().ClearAddrs(addr.ID)
	if err != nil {
		return err
	}
	return nil
}

func (n *Node) storagedata(peerid peer.ID, tracks []StorageDataType) error {
	account, _ := n.GetAccountByPeer(peerid.String())

	accountInfo, ok := n.GetPeerByAccount(account)
	if !ok {
		n.Logtrack("err", fmt.Sprintf(" %s peer not found account", peerid.String()))
		return nil
	}
	if accountInfo.State != schain.MINER_STATE_POSITIVE {
		n.Logtrack("err", fmt.Sprintf(" %s peer status is not %s", peerid.String(), schain.MINER_STATE_POSITIVE))
		return fmt.Errorf(" %s status is not %s", account, schain.MINER_STATE_POSITIVE)
	}
	if accountInfo.IdleSpace <= sconfig.FragmentSize*(sconfig.ParShards+sconfig.DataShards) {
		n.Logtrack("err", fmt.Sprintf(" %s peer space < 96M", peerid.String()))
		return fmt.Errorf(" %s space < 96M", account)
	}
	length := len(tracks)
	for i := 0; i < length; i++ {
		n.Logtrack("info", fmt.Sprintf(" %s peer will storage file %s", peerid.String(), tracks[i].Fid))
		if IsStoraged(account, tracks[i].Complete) {
			n.Logtrack("info", fmt.Sprintf(" %s peer already storage the file %s", peerid.String(), tracks[i].Fid))
			continue
		}
		err := n.storageBatchFragment(peerid, account, tracks[i])
		if err != nil {
			return err
		}
		if len(tracks[i].Data) > 1 {
			tracks[i].Data = tracks[i].Data[1:]
		} else {
			tracks[i].Data = make([][]string, 0)
		}
		accountInfo.IdleSpace -= sconfig.FragmentSize * (sconfig.ParShards + sconfig.DataShards)
		if accountInfo.IdleSpace <= sconfig.FragmentSize*(sconfig.ParShards+sconfig.DataShards) {
			n.Logtrack("info", fmt.Sprintf(" %s peer space is  < 96M", peerid.String()))
			return nil
		}
	}
	n.Logtrack("info", fmt.Sprintf(" %s peer all file transfred", peerid.String()))
	return nil
}

func (n *Node) storageBatchFragment(peerid peer.ID, account string, tracks StorageDataType) error {
	var err error
	if len(tracks.Data) <= 0 {
		n.Logtrack("info", fmt.Sprintf(" %s peer the file already transfered", peerid.String()))
		return nil
	}
	if len(tracks.Data[0]) <= 0 {
		n.Logtrack("info", fmt.Sprintf(" %s peer the file already transfered", peerid.String()))
		return nil
	}
	for j := 0; j < len(tracks.Data[0]); j++ {
		err = n.storageFragment(peerid, tracks.Fid, filepath.Base(tracks.Data[0][j]), tracks.Data[0][j])
		if err != nil {
			n.Logtrack("info", fmt.Sprintf(" %s peer transfer %d fragment failed: %v", peerid.String(), j, err))
			if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "i/o timeout") {
				n.AddToBlacklist(peerid.String(), account, err.Error())
			}
			return err
		}
		n.Logtrack("info", fmt.Sprintf(" %s peer transfer %d fragment suc", peerid.String(), j))
	}
	n.Logtrack("info", fmt.Sprintf(" %s peer transfer all fragment suc", peerid.String()))
	n.AddToWhitelist(peerid.String(), account)
	return nil
}

func (n *Node) storageFragment(peerid peer.ID, fid, fragmentHash, fragmentPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	defer cancel()
	err := n.WriteDataAction(ctx, peerid, fragmentPath, fid, fragmentHash)
	return err
}

func IsStoraged(account string, complete []string) bool {
	length := len(complete)
	for i := 0; i < length; i++ {
		if account == complete[i] {
			return true
		}
	}
	return false
}

func IsComplete(index int, completeInfo []schain.CompleteInfo) (string, bool) {
	length := len(completeInfo)
	for i := 0; i < length; i++ {
		if int(completeInfo[i].Index) == index {
			acc, _ := sutils.EncodePublicKeyAsCessAccount(completeInfo[i].Miner[:])
			return acc, true
		}
	}
	return "", false
}
