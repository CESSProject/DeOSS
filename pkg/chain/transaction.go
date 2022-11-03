/*
   Copyright 2022 CESS scheduler authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package chain

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/cess-scheduler/pkg/utils"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func (c *chainClient) Register(stash, ip, port string) (string, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	stashPuk, err := utils.DecodePublicKeyOfCessAccount(stash)
	if err != nil {
		return txhash, errors.Wrap(err, "DecodePublicKeyOfCessAccount")
	}

	var ipType IpAddress

	if utils.IsIPv4(ip) {
		ipType.IPv4.Index = 0
		ips := strings.Split(ip, ".")
		for i := 0; i < 4; i++ {
			temp, _ := strconv.Atoi(ips[i])
			ipType.IPv4.Value[i] = types.U8(temp)
		}
		temp, _ := strconv.Atoi(port)
		ipType.IPv4.Port = types.U16(temp)
	} else {
		return txhash, errors.New("unsupported ip format")
	}

	call, err := types.NewCall(
		c.metadata,
		tx_FileMap_Add_schedule,
		types.NewAccountID(stashPuk),
		ipType.IPv4,
	)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewCall]")
	}

	ext := types.NewExtrinsic(call)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewExtrinsic]")
	}

	key, err := types.CreateStorageKey(
		c.metadata,
		state_System,
		system_Account,
		c.keyring.PublicKey,
	)
	if err != nil {
		return txhash, errors.Wrap(err, "[CreateStorageKey]")
	}

	ok, err := c.api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "GetStorageLatest")
	}

	if !ok {
		return txhash, ERR_RPC_EMPTY_VALUE
	}

	o := types.SignatureOptions{
		BlockHash:          c.genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        c.genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        c.runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: c.runtimeVersion.TransactionVersion,
	}

	// Sign the transaction
	err = ext.Sign(c.keyring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "[Sign]")
	}

	// Do the transfer and track the actual status
	sub, err := c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		var tryCount = 0
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		for tryCount < 20 {
			o.Nonce = types.NewUCompactFromUInt(uint64(accountInfo.Nonce + types.NewU32(1)))
			// Sign the transaction
			err = ext.Sign(c.keyring, o)
			if err != nil {
				return txhash, errors.Wrap(err, "[Sign]")
			}
			sub, err = c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
			if err == nil {
				break
			}
			tryCount++
		}
	}
	if err != nil {
		return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
	}
	defer sub.Unsubscribe()
	timeout := time.After(c.timeForBlockOut)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := CessEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "GetStorageRaw")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.FileMap_RegistrationScheduler) > 0 {
					return txhash, nil
				}
				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "[sub]")
		case <-timeout:
			return txhash, ERR_RPC_TIMEOUT
		}
	}
}

// Update file meta information
func (c *chainClient) SubmitFileMeta(fid string, fsize uint64, block []BlockInfo) (string, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	var hash FileHash
	if len(fid) != len(hash) {
		return txhash, errors.New(ERR_Failed)
	}
	for i := 0; i < len(hash); i++ {
		hash[i] = types.U8(fid[i])
	}

	call, err := types.NewCall(
		c.metadata,
		tx_FileBank_Upload,
		hash,
		types.U64(fsize),
		block,
	)
	if err != nil {
		return txhash, errors.Wrap(err, "NewCall")
	}

	ext := types.NewExtrinsic(call)
	if err != nil {
		return txhash, errors.Wrap(err, "NewExtrinsic")
	}

	key, err := types.CreateStorageKey(
		c.metadata,
		state_System,
		system_Account,
		c.keyring.PublicKey,
	)
	if err != nil {
		return txhash, errors.Wrap(err, "CreateStorageKey")
	}

	ok, err := c.api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "GetStorageLatest err")
	}

	if !ok {
		return txhash, ERR_RPC_EMPTY_VALUE
	}

	o := types.SignatureOptions{
		BlockHash:          c.genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        c.genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        c.runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: c.runtimeVersion.TransactionVersion,
	}

	// Sign the transaction
	err = ext.Sign(c.keyring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "Sign")
	}

	// Do the transfer and track the actual status
	sub, err := c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		var tryCount = 0
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		for tryCount < 20 {
			o.Nonce = types.NewUCompactFromUInt(uint64(accountInfo.Nonce + types.NewU32(1)))
			// Sign the transaction
			err = ext.Sign(c.keyring, o)
			if err != nil {
				return txhash, errors.Wrap(err, "[Sign]")
			}
			sub, err = c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
			if err == nil {
				break
			}
			tryCount++
		}
	}
	if err != nil {
		return txhash, errors.Wrap(err, "SubmitAndWatchExtrinsic err")
	}
	defer sub.Unsubscribe()
	timeout := time.After(c.timeForBlockOut)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := CessEventRecords{}
				txhash = hex.EncodeToString(status.AsInBlock[:])
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "GetStorageRaw")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.FileBank_FileUpload) > 0 {
					return txhash, nil
				}
				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "sub")
		case <-timeout:
			return txhash, ERR_RPC_TIMEOUT
		}
	}
}

// Update file meta information
func (c *chainClient) SubmitFillerMeta(miner_acc types.AccountID, info []FillerMetaInfo) (string, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	call, err := types.NewCall(c.metadata, tx_FileBank_UploadFiller, miner_acc, info)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewCall]")
	}

	ext := types.NewExtrinsic(call)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewExtrinsic]")
	}

	key, err := types.CreateStorageKey(
		c.metadata,
		state_System,
		system_Account,
		c.keyring.PublicKey,
	)
	if err != nil {
		return txhash, errors.Wrap(err, "[CreateStorageKey]")
	}

	ok, err := c.api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "[GetStorageLatest]")
	}

	if !ok {
		return txhash, ERR_RPC_EMPTY_VALUE
	}

	o := types.SignatureOptions{
		BlockHash:          c.genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        c.genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        c.runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: c.runtimeVersion.TransactionVersion,
	}

	// Sign the transaction
	err = ext.Sign(c.keyring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "[Sign]")
	}

	// Do the transfer and track the actual status
	sub, err := c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		var tryCount = 0
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		for tryCount < 20 {
			o.Nonce = types.NewUCompactFromUInt(uint64(accountInfo.Nonce + types.NewU32(1)))
			// Sign the transaction
			err = ext.Sign(c.keyring, o)
			if err != nil {
				return txhash, errors.Wrap(err, "[Sign]")
			}
			sub, err = c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
			if err == nil {
				break
			}
			tryCount++
		}
	}
	if err != nil {
		return "", errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
	}
	defer sub.Unsubscribe()
	timeout := time.After(c.timeForBlockOut)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := CessEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "GetStorageRaw")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.FileBank_FillerUpload) > 0 {
					return txhash, nil
				}
				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "sub")
		case <-timeout:
			return txhash, ERR_RPC_TIMEOUT
		}
	}
}

func (c *chainClient) SubmitProofResults(data []ProofResult) (string, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	call, err := types.NewCall(c.metadata, tx_SegmentBook_VerifyProof, data)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewCall]")
	}

	ext := types.NewExtrinsic(call)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewExtrinsic]")
	}

	key, err := types.CreateStorageKey(
		c.metadata,
		state_System,
		system_Account,
		c.keyring.PublicKey,
	)
	if err != nil {
		return txhash, errors.Wrap(err, "[CreateStorageKey]")
	}

	ok, err := c.api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "[GetStorageLatest]")
	}
	if !ok {
		return txhash, ERR_RPC_EMPTY_VALUE
	}

	o := types.SignatureOptions{
		BlockHash:          c.genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        c.genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        c.runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: c.runtimeVersion.TransactionVersion,
	}

	// Sign the transaction
	err = ext.Sign(c.keyring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "[Sign]")
	}

	// Do the transfer and track the actual status
	sub, err := c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		var tryCount = 0
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		for tryCount < 20 {
			o.Nonce = types.NewUCompactFromUInt(uint64(accountInfo.Nonce + types.NewU32(1)))
			// Sign the transaction
			err = ext.Sign(c.keyring, o)
			if err != nil {
				return txhash, errors.Wrap(err, "[Sign]")
			}
			sub, err = c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
			if err == nil {
				break
			}
			tryCount++
		}
	}
	if err != nil {
		return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
	}

	defer sub.Unsubscribe()
	timeout := time.After(c.timeForBlockOut)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := CessEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "[GetStorageRaw]")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.SegmentBook_VerifyProof) > 0 {
					return txhash, nil
				}
				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "sub")
		case <-timeout:
			return txhash, ERR_RPC_TIMEOUT
		}
	}
}

func (c *chainClient) Update(ip, port string) (string, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	var ipType IpAddress

	if utils.IsIPv4(ip) {
		ipType.IPv4.Index = 0
		ips := strings.Split(ip, ".")
		for i := 0; i < 4; i++ {
			temp, _ := strconv.Atoi(ips[i])
			ipType.IPv4.Value[i] = types.U8(temp)
		}
		temp, _ := strconv.Atoi(port)
		ipType.IPv4.Port = types.U16(temp)
	} else {
		return txhash, errors.New("unsupported ip format")
	}

	call, err := types.NewCall(
		c.metadata,
		tx_FileMap_UpdateScheduler,
		ipType.IPv4,
	)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewCall]")
	}

	ext := types.NewExtrinsic(call)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewExtrinsic]")
	}

	key, err := types.CreateStorageKey(
		c.metadata,
		state_System,
		system_Account,
		c.keyring.PublicKey,
	)
	if err != nil {
		return txhash, errors.Wrap(err, "[CreateStorageKey]")
	}

	ok, err := c.api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "[GetStorageLatest]")
	}
	if !ok {
		return txhash, ERR_RPC_EMPTY_VALUE
	}

	o := types.SignatureOptions{
		BlockHash:          c.genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        c.genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        c.runtimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: c.runtimeVersion.TransactionVersion,
	}

	// Sign the transaction
	err = ext.Sign(c.keyring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "[Sign]")
	}

	// Do the transfer and track the actual status
	sub, err := c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		var tryCount = 0
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		for tryCount < 20 {
			o.Nonce = types.NewUCompactFromUInt(uint64(accountInfo.Nonce + types.NewU32(1)))
			// Sign the transaction
			err = ext.Sign(c.keyring, o)
			if err != nil {
				return txhash, errors.Wrap(err, "[Sign]")
			}
			sub, err = c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
			if err == nil {
				break
			}
			tryCount++
		}
	}
	if err != nil {
		return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
	}
	defer sub.Unsubscribe()
	timeout := time.After(c.timeForBlockOut)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := CessEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "[GetStorageRaw]")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.FileMap_UpdateScheduler) > 0 {
					return txhash, nil
				}
				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "sub")
		case <-timeout:
			return txhash, ERR_RPC_TIMEOUT
		}
	}
}
