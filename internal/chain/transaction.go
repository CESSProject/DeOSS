package chain

import (
	"cess-gateway/configs"
	. "cess-gateway/internal/logger"
	"cess-gateway/tools"
	"time"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func UploadDeclaration(transactionPrK, filehash, filename string) (string, error) {
	defer func() {
		if err := recover(); err != nil {
			Err.Sugar().Errorf("%v", tools.RecoverError(err))
		}
	}()

	var txhash string
	var accountInfo types.AccountInfo

	api, err := GetRpcClient_Safe(configs.C.RpcAddr)
	defer Free()
	if err != nil {
		return txhash, errors.Wrap(err, "[GetRpcClient_Safe]")
	}

	meta, err := GetMetadata(api)
	if err != nil {
		return txhash, errors.Wrap(err, "[GetMetadataLatest]")
	}

	var hash FileHash
	if len(filehash) != len(hash) {
		return txhash, errors.New("invalid filehash")
	}
	for i := 0; i < len(hash); i++ {
		hash[i] = types.U8(filehash[i])
	}

	c, err := types.NewCall(meta, ChainTx_FileBank_UploadDeclaration, hash, types.NewBytes([]byte(filename)))
	if err != nil {
		return txhash, errors.Wrap(err, "[NewCall]")
	}

	ext := types.NewExtrinsic(c)
	if err != nil {
		return txhash, errors.Wrap(err, "[NewExtrinsic]")
	}

	genesisHash, err := GetGenesisHash(api)
	if err != nil {
		return txhash, errors.Wrap(err, "[GetGenesisHash]")
	}

	rv, err := GetRuntimeVersion(api)
	if err != nil {
		return txhash, errors.Wrap(err, "[GetRuntimeVersion]")
	}

	key, err := types.CreateStorageKey(meta, "System", "Account", configs.PublicKey, nil)
	if err != nil {
		return txhash, errors.Wrap(err, "[CreateStorageKey]")
	}

	ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "[GetStorageLatest]")
	}
	if !ok {
		return txhash, errors.New(ERR_Empty)
	}

	o := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        rv.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: rv.TransactionVersion,
	}

	kring, err := GetKeyring()
	if err != nil {
		return txhash, errors.Wrap(err, "GetKeyring")
	}

	// Sign the transaction
	err = ext.Sign(kring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "[Sign]")
	}

	// Do the transfer and track the actual status
	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		return txhash, errors.Wrap(err, "[SubmitAndWatchExtrinsic]")
	}
	defer sub.Unsubscribe()
	timeout := time.After(configs.TimeToWaitEvents)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := MyEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				keye, err := GetKeyEvents()
				if err != nil {
					return txhash, errors.Wrap(err, "GetKeyEvents")
				}
				h, err := api.RPC.State.GetStorageRaw(keye, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "GetStorageRaw")
				}

				err = types.EventRecordsRaw(*h).DecodeEventRecords(meta, &events)
				if err != nil {
					Out.Sugar().Infof("[%v]Decode event err:%v", txhash, err)
				}

				if len(events.FileBank_UploadDeclaration) > 0 {
					for i := 0; i < len(events.FileBank_UploadDeclaration); i++ {
						if string(events.FileBank_UploadDeclaration[i].File_hash) == filehash {
							return txhash, nil
						}
					}
				}
				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "<-sub")
		case <-timeout:
			return txhash, errors.New(ERR_Timeout)
		}
	}
}

// Delete files in chain
func DeleteFileOnChain(phrase, fid string) (string, error) {
	defer func() {
		if err := recover(); err != nil {
			Err.Sugar().Errorf("%v", tools.RecoverError(err))
		}
	}()

	var txhash string
	var accountInfo types.AccountInfo

	api, err := GetRpcClient_Safe(configs.C.RpcAddr)
	defer Free()
	if err != nil {
		return txhash, errors.Wrap(err, "GetRpcClient_Safe")
	}

	meta, err := GetMetadata(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetMetadataLatest")
	}

	var hash FileHash
	if len(fid) != len(hash) {
		return txhash, errors.New("invalid filehash")
	}
	for i := 0; i < len(hash); i++ {
		hash[i] = types.U8(fid[i])
	}

	c, err := types.NewCall(meta, ChainTx_FileBank_DeleteFile, hash)
	if err != nil {
		return txhash, errors.Wrap(err, "NewCall")
	}

	ext := types.NewExtrinsic(c)
	if err != nil {
		return txhash, errors.Wrap(err, "NewExtrinsic")
	}

	genesisHash, err := GetGenesisHash(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetGenesisHash")
	}

	rv, err := GetRuntimeVersion(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetRuntimeVersion")
	}

	key, err := types.CreateStorageKey(meta, "System", "Account", configs.PublicKey, nil)
	if err != nil {
		return txhash, errors.Wrap(err, "CreateStorageKey")
	}

	ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "GetStorageLatest")
	}

	if !ok {
		return txhash, errors.New(ERR_Empty)
	}

	o := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        rv.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: rv.TransactionVersion,
	}

	kring, err := GetKeyring()
	if err != nil {
		return txhash, errors.Wrap(err, "GetKeyring")
	}

	// Sign the transaction
	err = ext.Sign(kring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "Sign")
	}

	// Do the transfer and track the actual status
	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		return txhash, errors.Wrap(err, "SubmitAndWatchExtrinsic")
	}
	defer sub.Unsubscribe()
	timeout := time.After(configs.TimeToWaitEvents)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := MyEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				keye, err := GetKeyEvents()
				if err != nil {
					return txhash, errors.Wrap(err, "GetKeyEvents")
				}
				h, err := api.RPC.State.GetStorageRaw(keye, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "GetStorageRaw")
				}

				err = types.EventRecordsRaw(*h).DecodeEventRecords(meta, &events)
				if err != nil {
					Out.Sugar().Infof("[%v]Decode event err:%v", txhash, err)
				}

				if len(events.FileBank_DeleteFile) > 0 {
					for i := 0; i < len(events.FileBank_DeleteFile); i++ {
						if string(events.FileBank_DeleteFile[i].Acc[:]) == string(configs.PublicKey) {
							return txhash, nil
						}
					}
				}
				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "<-sub")
		case <-timeout:
			return txhash, errors.New(ERR_Timeout)
		}
	}
}

func GetPubkeyFromPrk(prk string) ([]byte, error) {
	keyring, err := signature.KeyringPairFromSecret(prk, 0)
	if err != nil {
		return nil, errors.Wrap(err, "[KeyringPairFromSecret]")
	}
	return keyring.PublicKey, nil
}

func BuySpacePackage(package_type types.U8, count types.U128) (string, error) {
	defer func() {
		if err := recover(); err != nil {
			Err.Sugar().Errorf("%v", tools.RecoverError(err))
		}
	}()

	var txhash string
	var accountInfo types.AccountInfo

	api, err := NewRpcClient(configs.C.RpcAddr)
	if err != nil {
		return txhash, errors.Wrap(err, "NewRpcClient")
	}

	meta, err := GetMetadata(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetMetadata")
	}

	c, err := types.NewCall(meta, ChainTx_FileBank_BuyPackage, package_type, count)
	if err != nil {
		return txhash, errors.Wrap(err, "NewCall")
	}

	ext := types.NewExtrinsic(c)
	if err != nil {
		return txhash, errors.Wrap(err, "NewExtrinsic")
	}

	genesisHash, err := GetGenesisHash(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetGenesisHash")
	}

	rv, err := GetRuntimeVersion(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetRuntimeVersion")
	}

	key, err := types.CreateStorageKey(meta, "System", "Account", configs.PublicKey, nil)
	if err != nil {
		return txhash, errors.Wrap(err, "CreateStorageKey")
	}

	ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "GetStorageLatest")
	}

	if !ok {
		return txhash, errors.New(ERR_Empty)
	}

	o := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        rv.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: rv.TransactionVersion,
	}

	kring, err := GetKeyring()
	if err != nil {
		return txhash, errors.Wrap(err, "GetKeyring")
	}

	// Sign the transaction
	err = ext.Sign(kring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "Sign")
	}

	// Do the transfer and track the actual status
	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		return txhash, errors.Wrap(err, "SubmitAndWatchExtrinsic")
	}

	defer sub.Unsubscribe()
	timeout := time.After(configs.TimeToWaitEvents)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := MyEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				keye, err := GetKeyEvents()
				if err != nil {
					return txhash, errors.Wrap(err, "GetKeyEvents")
				}
				h, err := api.RPC.State.GetStorageRaw(keye, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "GetStorageRaw")
				}
				err = types.EventRecordsRaw(*h).DecodeEventRecords(meta, &events)
				if err != nil {
					Out.Sugar().Infof("[%v]Decode event err:%v", txhash, err)
				}

				if len(events.FileBank_BuyPackage) > 0 {
					return txhash, nil
				}

				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "<-sub")
		case <-timeout:
			return txhash, errors.New(ERR_Timeout)
		}
	}
}

func UpgradeSpacePackage(package_type types.U8, count types.U128) (string, error) {
	defer func() {
		if err := recover(); err != nil {
			Err.Sugar().Errorf("%v", tools.RecoverError(err))
		}
	}()

	var txhash string
	var accountInfo types.AccountInfo

	api, err := NewRpcClient(configs.C.RpcAddr)
	if err != nil {
		return txhash, errors.Wrap(err, "NewRpcClient")
	}

	meta, err := GetMetadata(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetMetadata")
	}

	c, err := types.NewCall(meta, ChainTx_FileBank_UpgradePackage, package_type, count)
	if err != nil {
		return txhash, errors.Wrap(err, "NewCall")
	}

	ext := types.NewExtrinsic(c)
	if err != nil {
		return txhash, errors.Wrap(err, "NewExtrinsic")
	}

	genesisHash, err := GetGenesisHash(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetGenesisHash")
	}

	rv, err := GetRuntimeVersion(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetRuntimeVersion")
	}

	key, err := types.CreateStorageKey(meta, "System", "Account", configs.PublicKey, nil)
	if err != nil {
		return txhash, errors.Wrap(err, "CreateStorageKey")
	}

	ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "GetStorageLatest")
	}

	if !ok {
		return txhash, errors.New(ERR_Empty)
	}

	o := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        rv.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: rv.TransactionVersion,
	}

	kring, err := GetKeyring()
	if err != nil {
		return txhash, errors.Wrap(err, "GetKeyring")
	}

	// Sign the transaction
	err = ext.Sign(kring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "Sign")
	}

	// Do the transfer and track the actual status
	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		return txhash, errors.Wrap(err, "SubmitAndWatchExtrinsic")
	}

	defer sub.Unsubscribe()
	timeout := time.After(configs.TimeToWaitEvents)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := MyEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				keye, err := GetKeyEvents()
				if err != nil {
					return txhash, errors.Wrap(err, "GetKeyEvents")
				}
				h, err := api.RPC.State.GetStorageRaw(keye, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "GetStorageRaw")
				}
				err = types.EventRecordsRaw(*h).DecodeEventRecords(meta, &events)
				if err != nil {
					Out.Sugar().Infof("[%v]Decode event err:%v", txhash, err)
				}

				if len(events.FileBank_PackageUpgrade) > 0 {
					for i := 0; i < len(events.FileBank_PackageUpgrade); i++ {
						if events.FileBank_PackageUpgrade[i].Acc == types.NewAccountID(configs.PublicKey) {
							return txhash, nil
						}
					}
				}

				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "<-sub")
		case <-timeout:
			return txhash, errors.New(ERR_Timeout)
		}
	}
}

func Renewal() (string, error) {
	defer func() {
		if err := recover(); err != nil {
			Err.Sugar().Errorf("%v", tools.RecoverError(err))
		}
	}()

	var txhash string
	var accountInfo types.AccountInfo

	api, err := NewRpcClient(configs.C.RpcAddr)
	if err != nil {
		return txhash, errors.Wrap(err, "NewRpcClient")
	}

	meta, err := GetMetadata(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetMetadata")
	}

	c, err := types.NewCall(meta, ChainTx_FileBank_RenewalPackage)
	if err != nil {
		return txhash, errors.Wrap(err, "NewCall")
	}

	ext := types.NewExtrinsic(c)
	if err != nil {
		return txhash, errors.Wrap(err, "NewExtrinsic")
	}

	genesisHash, err := GetGenesisHash(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetGenesisHash")
	}

	rv, err := GetRuntimeVersion(api)
	if err != nil {
		return txhash, errors.Wrap(err, "GetRuntimeVersion")
	}

	key, err := types.CreateStorageKey(meta, "System", "Account", configs.PublicKey, nil)
	if err != nil {
		return txhash, errors.Wrap(err, "CreateStorageKey")
	}

	ok, err := api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return txhash, errors.Wrap(err, "GetStorageLatest")
	}

	if !ok {
		return txhash, errors.New(ERR_Empty)
	}

	o := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        rv.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: rv.TransactionVersion,
	}

	kring, err := GetKeyring()
	if err != nil {
		return txhash, errors.Wrap(err, "GetKeyring")
	}

	// Sign the transaction
	err = ext.Sign(kring, o)
	if err != nil {
		return txhash, errors.Wrap(err, "Sign")
	}

	// Do the transfer and track the actual status
	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		return txhash, errors.Wrap(err, "SubmitAndWatchExtrinsic")
	}

	defer sub.Unsubscribe()
	timeout := time.After(configs.TimeToWaitEvents)
	for {
		select {
		case status := <-sub.Chan():
			if status.IsInBlock {
				events := MyEventRecords{}
				txhash, _ = types.EncodeToHex(status.AsInBlock)
				keye, err := GetKeyEvents()
				if err != nil {
					return txhash, errors.Wrap(err, "GetKeyEvents")
				}
				h, err := api.RPC.State.GetStorageRaw(keye, status.AsInBlock)
				if err != nil {
					return txhash, errors.Wrap(err, "GetStorageRaw")
				}
				err = types.EventRecordsRaw(*h).DecodeEventRecords(meta, &events)
				if err != nil {
					Out.Sugar().Infof("[%v]Decode event err:%v", txhash, err)
				}

				if len(events.FileBank_PackageRenewal) > 0 {
					for i := 0; i < len(events.FileBank_PackageRenewal); i++ {
						if events.FileBank_PackageRenewal[i].Acc == types.NewAccountID(configs.PublicKey) {
							return txhash, nil
						}
					}
				}

				return txhash, errors.New(ERR_Failed)
			}
		case err = <-sub.Err():
			return txhash, errors.Wrap(err, "<-sub")
		case <-timeout:
			return txhash, errors.New(ERR_Timeout)
		}
	}
}
