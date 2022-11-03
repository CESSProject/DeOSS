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
	"sync"
	"sync/atomic"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

type Chainer interface {
	// Getpublickey returns its own public key
	GetPublicKey() []byte
	// GetStashPublicKey returns its stash account public key
	GetStashPublicKey() ([]byte, error)
	// Getpublickey returns its own private key
	GetMnemonicSeed() string
	// NewAccountId returns the account id
	NewAccountId(pubkey []byte) types.AccountID
	// GetSyncStatus returns whether the block is being synchronized
	GetSyncStatus() (bool, error)
	// GetChainStatus returns chain status
	GetChainStatus() bool
	// Getstorageminerinfo is used to get the details of the miner
	GetStorageMinerInfo(pkey []byte) (MinerInfo, error)
	// Getallstorageminer is used to obtain the AccountID of all miners
	GetAllStorageMiner() ([]types.AccountID, error)
	// GetFileMetaInfo is used to get the meta information of the file
	GetFileMetaInfo(fid types.Bytes) (FileMetaInfo, error)
	// GetAllSchedulerInfo is used to get information about all schedules
	GetAllSchedulerInfo() ([]SchedulerInfo, error)
	// GetProofs is used to get all the proofs to be verified
	GetProofs() ([]Proof, error)
	// GetCessAccount is used to get the account in cess chain format
	GetCessAccount() (string, error)
	// GetAccountInfo is used to get account information
	GetAccountInfo(pkey []byte) (types.AccountInfo, error)
	// GetSpacePackageInfo is used to get the space package information of the account
	GetSpacePackageInfo(pkey []byte) (SpacePackage, error)
	// Register is used by the scheduling service to register
	Register(stash, ip, port string) (string, error)
	// SubmitProofResults is used to submit proof verification results
	SubmitProofResults(data []ProofResult) (string, error)
	// SubmitFillerMeta is used to submit the meta information of the filler
	SubmitFillerMeta(miner_acc types.AccountID, info []FillerMetaInfo) (string, error)
	// SubmitFileMeta is used to submit the meta information of the file
	SubmitFileMeta(fid string, fsize uint64, block []BlockInfo) (string, error)
	// Update is used to update the communication address of the scheduling service
	Update(ip, port string) (string, error)
}

type chainClient struct {
	lock            *sync.Mutex
	api             *gsrpc.SubstrateAPI
	chainState      *atomic.Bool
	metadata        *types.Metadata
	runtimeVersion  *types.RuntimeVersion
	keyEvents       types.StorageKey
	genesisHash     types.Hash
	keyring         signature.KeyringPair
	rpcAddr         string
	stash           string
	timeForBlockOut time.Duration
}

func NewChainClient(rpcAddr, secret, stash string, t time.Duration) (Chainer, error) {
	var (
		err error
		cli = &chainClient{}
	)
	cli.api, err = gsrpc.NewSubstrateAPI(rpcAddr)
	if err != nil {
		return nil, err
	}
	cli.metadata, err = cli.api.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil, err
	}
	cli.genesisHash, err = cli.api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		return nil, err
	}
	cli.runtimeVersion, err = cli.api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		return nil, err
	}
	cli.keyEvents, err = types.CreateStorageKey(
		cli.metadata,
		state_System,
		system_Events,
		nil,
	)
	if err != nil {
		return nil, err
	}
	if secret != "" {
		cli.keyring, err = signature.KeyringPairFromSecret(secret, 0)
		if err != nil {
			return nil, err
		}
	}
	cli.lock = new(sync.Mutex)
	cli.chainState = &atomic.Bool{}
	cli.chainState.Store(true)
	cli.timeForBlockOut = t
	cli.rpcAddr = rpcAddr
	cli.stash = stash
	return cli, nil
}

func (c *chainClient) IsChainClientOk() bool {
	err := healthchek(c.api)
	if err != nil {
		c.api = nil
		cli, err := reconnectChainClient(c.rpcAddr)
		if err != nil {
			return false
		}
		c.api = cli
		return true
	}
	return true
}

func (c *chainClient) SetChainState(state bool) {
	c.chainState.Store(state)
}

func (c *chainClient) GetChainState() bool {
	return c.chainState.Load()
}

func (c *chainClient) NewAccountId(pubkey []byte) types.AccountID {
	return types.NewAccountID(pubkey)
}

func reconnectChainClient(rpcAddr string) (*gsrpc.SubstrateAPI, error) {
	return gsrpc.NewSubstrateAPI(rpcAddr)
}

func healthchek(a *gsrpc.SubstrateAPI) error {
	defer func() {
		recover()
	}()
	_, err := a.RPC.System.Health()
	return err
}
