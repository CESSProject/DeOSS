/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package chain

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func (c *chainClient) Register(ip, port string) (string, error) {
	var (
		txhash      string
		ipType      IpAddress
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer func() {
		c.lock.Unlock()
		if err := recover(); err != nil {
			fmt.Println(utils.RecoverError(err))
		}
	}()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	if utils.IsIPv4(ip) {
		ipType.IPv4.Index = 0
		ips := strings.Split(ip, ".")
		for i := 0; i < len(ipType.IPv4.Value); i++ {
			temp, _ := strconv.Atoi(ips[i])
			ipType.IPv4.Value[i] = types.U8(temp)
		}
		temp, _ := strconv.Atoi(port)
		ipType.IPv4.Port = types.U16(temp)
	} else {
		return txhash, ERR_RPC_IP_FORMAT
	}

	call, err := types.NewCall(
		c.metadata,
		TX_OSS_REGISTER,
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
		SYSTEM,
		ACCOUNT,
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
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		var tryCount = 0
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
				events := EventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "[GetStorageRaw]")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.Oss_OssRegister) > 0 {
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

func (c *chainClient) Update(ip, port string) (string, error) {
	var (
		txhash      string
		ipType      IpAddress
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer func() {
		c.lock.Unlock()
		if err := recover(); err != nil {
			fmt.Println(utils.RecoverError(err))
		}
	}()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	if utils.IsIPv4(ip) {
		ipType.IPv4.Index = 0
		ips := strings.Split(ip, ".")
		for i := 0; i < len(ipType.IPv4.Value); i++ {
			temp, _ := strconv.Atoi(ips[i])
			ipType.IPv4.Value[i] = types.U8(temp)
		}
		temp, _ := strconv.Atoi(port)
		ipType.IPv4.Port = types.U16(temp)
	} else {
		return txhash, ERR_RPC_IP_FORMAT
	}

	call, err := types.NewCall(
		c.metadata,
		TX_OSS_UPDATE,
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
		SYSTEM,
		ACCOUNT,
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
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		var tryCount = 0
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
				events := EventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "[GetStorageRaw]")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.Oss_OssUpdate) > 0 {
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

func (c *chainClient) CreateBucket(owner_pkey []byte, name string) (string, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer func() {
		c.lock.Unlock()
		if err := recover(); err != nil {
			fmt.Println(utils.RecoverError(err))
		}
	}()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	// b, err := types.Encode(name)
	// if err != nil {
	// 	return txhash, errors.Wrap(err, "[Encode]")
	// }
	call, err := types.NewCall(
		c.metadata,
		TX_FILEBANK_PUTBUCKET,
		types.NewAccountID(owner_pkey),
		types.NewBytes([]byte(name)),
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
		SYSTEM,
		ACCOUNT,
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
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		var tryCount = 0
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
				events := EventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "[GetStorageRaw]")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.FileBank_CreateBucket) > 0 {
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

func (c *chainClient) DeleteBucket(owner_pkey []byte, name string) (string, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer func() {
		c.lock.Unlock()
		if err := recover(); err != nil {
			fmt.Println(utils.RecoverError(err))
		}
	}()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	call, err := types.NewCall(
		c.metadata,
		TX_FILEBANK_DELBUCKET,
		types.NewAccountID(owner_pkey),
		types.NewBytes([]byte(name)),
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
		SYSTEM,
		ACCOUNT,
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
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		var tryCount = 0
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
				events := EventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "[GetStorageRaw]")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.FileBank_DeleteBucket) > 0 {
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

func (c *chainClient) DeclarationFile(filehash string, user UserBrief) (string, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer func() {
		c.lock.Unlock()
		if err := recover(); err != nil {
			fmt.Println(utils.RecoverError(err))
		}
	}()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	var hash FileHash
	if len(filehash) != len(hash) {
		return txhash, errors.New("invalid filehash")
	}
	for i := 0; i < len(hash); i++ {
		hash[i] = types.U8(filehash[i])
	}

	call, err := types.NewCall(
		c.metadata,
		TX_FILEBANK_UPLOADDEC,
		hash,
		user,
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
		SYSTEM,
		ACCOUNT,
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
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		var tryCount = 0
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
				events := EventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "[GetStorageRaw]")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.FileBank_UploadDeclaration) > 0 {
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

func (c *chainClient) DeleteFile(owner_pkey []byte, filehash []string) (string, []FileHash, error) {
	var (
		txhash      string
		accountInfo types.AccountInfo
	)

	c.lock.Lock()
	defer func() {
		c.lock.Unlock()
		if err := recover(); err != nil {
			fmt.Println(utils.RecoverError(err))
		}
	}()

	if !c.IsChainClientOk() {
		c.SetChainState(false)
		return txhash, nil, ERR_RPC_CONNECTION
	}
	c.SetChainState(true)

	var hash = make([]FileHash, len(filehash))

	for j := 0; j < len(filehash); j++ {
		if len(filehash[j]) != len(hash[j]) {
			return txhash, nil, errors.New("invalid filehash")
		}
		for i := 0; i < len(hash[j]); i++ {
			hash[j][i] = types.U8(filehash[j][i])
		}
	}

	fmt.Println(hash)

	call, err := types.NewCall(
		c.metadata,
		TX_FILEBANK_DELFILE,
		types.NewAccountID(owner_pkey),
		hash,
	)
	if err != nil {
		return txhash, nil, errors.Wrap(err, "[NewCall]")
	}

	ext := types.NewExtrinsic(call)
	if err != nil {
		return txhash, nil, errors.Wrap(err, "[NewExtrinsic]")
	}

	key, err := types.CreateStorageKey(
		c.metadata,
		SYSTEM,
		ACCOUNT,
		c.keyring.PublicKey,
	)
	if err != nil {
		return txhash, nil, errors.Wrap(err, "[CreateStorageKey]")
	}

	ok, err := c.api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, nil, errors.Wrap(err, "[GetStorageLatest]")
	}
	if !ok {
		return txhash, hash, ERR_RPC_EMPTY_VALUE
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
		return txhash, nil, errors.Wrap(err, "[Sign]")
	}

	// Do the transfer and track the actual status
	sub, err := c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		if !strings.Contains(err.Error(), "Priority is too low") {
			return txhash, nil, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
		}
		var tryCount = 0
		for tryCount < 20 {
			o.Nonce = types.NewUCompactFromUInt(uint64(accountInfo.Nonce + types.NewU32(1)))
			// Sign the transaction
			err = ext.Sign(c.keyring, o)
			if err != nil {
				return txhash, nil, errors.Wrap(err, "[Sign]")
			}
			sub, err = c.api.RPC.Author.SubmitAndWatchExtrinsic(ext)
			if err == nil {
				break
			}
			tryCount++
		}
	}
	if err != nil {
		return txhash, nil, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
	}
	defer sub.Unsubscribe()
	timeout := time.After(c.timeForBlockOut)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := EventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				h, err := c.api.RPC.State.GetStorageRaw(c.keyEvents, status.AsInBlock)
				if err != nil {
					return txhash, nil, errors.Wrap(err, "[GetStorageRaw]")
				}

				types.EventRecordsRaw(*h).DecodeEventRecords(c.metadata, &events)

				if len(events.FileBank_DeleteFile) > 0 {
					return txhash, events.FileBank_DeleteFile[0].FailedList, nil
				}
				return txhash, nil, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, nil, errors.Wrap(err, "[sub]")
		case <-timeout:
			return txhash, nil, ERR_RPC_TIMEOUT
		}
	}
}
