/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package chain

import "github.com/centrifuge/go-substrate-rpc-client/v4/types"

// ******************************************************
// cess event type
// ******************************************************

// ------------------------SegmentBook-------------------
type Event_PPBNoOnTimeSubmit struct {
	Phase     types.Phase
	Acc       types.AccountID
	SegmentId types.U64
	Topics    []types.Hash
}

type Event_PPDNoOnTimeSubmit struct {
	Phase     types.Phase
	Acc       types.AccountID
	SegmentId types.U64
	Topics    []types.Hash
}

type Event_ChallengeProof struct {
	Phase  types.Phase
	Miner  types.AccountID
	Fileid types.Bytes
	Topics []types.Hash
}

type Event_VerifyProof struct {
	Phase  types.Phase
	Miner  types.AccountID
	Fileid types.Bytes
	Topics []types.Hash
}

type Event_OutstandingChallenges struct {
	Phase  types.Phase
	Miner  types.AccountID
	Fileid types.Bytes
	Topics []types.Hash
}

// ------------------------Sminer------------------------
type Event_Registered struct {
	Phase      types.Phase
	Acc        types.AccountID
	StakingVal types.U128
	Topics     []types.Hash
}

type Event_TimedTask struct {
	Phase  types.Phase
	Topics []types.Hash
}

type Event_DrawFaucetMoney struct {
	Phase  types.Phase
	Topics []types.Hash
}

type Event_FaucetTopUpMoney struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type Event_LessThan24Hours struct {
	Phase  types.Phase
	Last   types.U32
	Now    types.U32
	Topics []types.Hash
}
type Event_AlreadyFrozen struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type Event_MinerExit struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type Event_MinerClaim struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type Event_IncreaseCollateral struct {
	Phase   types.Phase
	Acc     types.AccountID
	Balance types.U128
	Topics  []types.Hash
}

type Event_Deposit struct {
	Phase   types.Phase
	Balance types.U128
	Topics  []types.Hash
}

type Event_Redeemed struct {
	Phase   types.Phase
	Acc     types.AccountID
	Deposit types.U128
	Topics  []types.Hash
}

type Event_Claimed struct {
	Phase   types.Phase
	Acc     types.AccountID
	Deposit types.U128
	Topics  []types.Hash
}

type Event_TimingStorageSpace struct {
	Phase  types.Phase
	Topics []types.Hash
}

type Event_UpdataBeneficiary struct {
	Phase  types.Phase
	Acc    types.AccountID
	New    types.AccountID
	Topics []types.Hash
}

type Event_UpdataIp struct {
	Phase  types.Phase
	Acc    types.AccountID
	Old    Ipv4Type
	New    Ipv4Type
	Topics []types.Hash
}

type Event_StartOfBufferPeriod struct {
	Phase  types.Phase
	When   types.U32
	Topics []types.Hash
}

type Event_EndOfBufferPeriod struct {
	Phase  types.Phase
	When   types.U32
	Topics []types.Hash
}

// ------------------------FileBank----------------------
type Event_DeleteFile struct {
	Phase      types.Phase
	Acc        types.AccountID
	Owner      types.AccountID
	Filehashs  []FileHash
	FailedList []FileHash
	Topics     []types.Hash
}

type Event_FileUpload struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type Event_FileUpdate struct {
	Phase  types.Phase
	Acc    types.AccountID
	Fileid types.Bytes
	Topics []types.Hash
}

type Event_FileChangeState struct {
	Phase  types.Phase
	Acc    types.AccountID
	Fileid types.Bytes
	Topics []types.Hash
}

type Event_BuyFile struct {
	Phase  types.Phase
	Acc    types.AccountID
	Money  types.U128
	Fileid types.Bytes
	Topics []types.Hash
}

type Event_Purchased struct {
	Phase  types.Phase
	Acc    types.AccountID
	Fileid types.Bytes
	Topics []types.Hash
}

type Event_InsertFileSlice struct {
	Phase  types.Phase
	Fileid types.Bytes
	Topics []types.Hash
}

type Event_FillerUpload struct {
	Phase    types.Phase
	Acc      types.AccountID
	Filesize types.U64
	Topics   []types.Hash
}

type Event_ClearInvalidFile struct {
	Phase     types.Phase
	Acc       types.AccountID
	File_hash [64]types.U8
	Topics    []types.Hash
}

type Event_RecoverFile struct {
	Phase     types.Phase
	Acc       types.AccountID
	File_hash [68]types.U8
	Topics    []types.Hash
}

type Event_ReceiveSpace struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type Event_UploadDeclaration struct {
	Phase     types.Phase
	Acc       types.AccountID
	Owner     types.AccountID
	File_hash FileHash
	File_name types.Bytes
	Topics    []types.Hash
}

type Event_CreateBucket struct {
	Phase       types.Phase
	Acc         types.AccountID
	Owner       types.AccountID
	Bucket_name types.Bytes
	Topics      []types.Hash
}

type Event_DeleteBucket struct {
	Phase       types.Phase
	Acc         types.AccountID
	Owner       types.AccountID
	Bucket_name types.Bytes
	Topics      []types.Hash
}

// ------------------------StorageHandler--------------------------------
type Event_BuySpace struct {
	Phase            types.Phase
	Acc              types.AccountID
	Storage_capacity types.U128
	Spend            types.U128
	Topics           []types.Hash
}

type Event_ExpansionSpace struct {
	Phase           types.Phase
	Acc             types.AccountID
	Expansion_space types.U128
	Fee             types.U128
	Topics          []types.Hash
}

type Event_RenewalSpace struct {
	Phase        types.Phase
	Acc          types.AccountID
	Renewal_days types.U32
	Fee          types.U128
	Topics       []types.Hash
}

type Event_LeaseExpired struct {
	Phase  types.Phase
	Acc    types.AccountID
	Size   types.U128
	Topics []types.Hash
}

type Event_LeaseExpireIn24Hours struct {
	Phase  types.Phase
	Acc    types.AccountID
	Size   types.U128
	Topics []types.Hash
}

// ------------------------TEE Worker--------------------
type Event_RegistrationScheduler struct {
	Phase  types.Phase
	Acc    types.AccountID
	Ip     Ipv4Type
	Topics []types.Hash
}

type Event_UpdateScheduler struct {
	Phase    types.Phase
	Acc      types.AccountID
	Endpoint Ipv4Type
	Topics   []types.Hash
}

// ------------------------Oss---------------------------
type Event_OssRegister struct {
	Phase    types.Phase
	Acc      types.AccountID
	Endpoint Ipv4Type
	Topics   []types.Hash
}

type Event_OssUpdate struct {
	Phase        types.Phase
	Acc          types.AccountID
	New_endpoint Ipv4Type
	Topics       []types.Hash
}

// ------------------------System------------------------
type Event_UnsignedPhaseStarted struct {
	Phase  types.Phase
	Round  types.U32
	Topics []types.Hash
}

type Event_SignedPhaseStarted struct {
	Phase  types.Phase
	Round  types.U32
	Topics []types.Hash
}

type Event_SolutionStored struct {
	Phase            types.Phase
	Election_compute types.ElectionCompute
	Prev_ejected     types.Bool
	Topics           []types.Hash
}

type Event_Balances_Withdraw struct {
	Phase  types.Phase
	Who    types.AccountID
	Amount types.U128
	Topics []types.Hash
}

//*******************************************************

// Events
type EventRecords struct {
	// AUDIT
	SegmentBook_PPBNoOnTimeSubmit     []Event_PPBNoOnTimeSubmit
	SegmentBook_PPDNoOnTimeSubmit     []Event_PPDNoOnTimeSubmit
	SegmentBook_ChallengeProof        []Event_ChallengeProof
	SegmentBook_VerifyProof           []Event_VerifyProof
	SegmentBook_OutstandingChallenges []Event_OutstandingChallenges
	// SMINER
	Sminer_Registered          []Event_Registered
	Sminer_TimedTask           []Event_TimedTask
	Sminer_DrawFaucetMoney     []Event_DrawFaucetMoney
	Sminer_FaucetTopUpMoney    []Event_FaucetTopUpMoney
	Sminer_LessThan24Hours     []Event_LessThan24Hours
	Sminer_AlreadyFrozen       []Event_AlreadyFrozen
	Sminer_MinerExit           []Event_MinerExit
	Sminer_MinerClaim          []Event_MinerClaim
	Sminer_IncreaseCollateral  []Event_IncreaseCollateral
	Sminer_Deposit             []Event_Deposit
	Sminer_Redeemed            []Event_Redeemed
	Sminer_Claimed             []Event_Claimed
	Sminer_TimingStorageSpace  []Event_TimingStorageSpace
	Sminer_UpdataBeneficiary   []Event_UpdataBeneficiary
	Sminer_UpdataIp            []Event_UpdataIp
	Sminer_StartOfBufferPeriod []Event_StartOfBufferPeriod
	Sminer_EndOfBufferPeriod   []Event_EndOfBufferPeriod
	// FILEBANK
	FileBank_DeleteFile        []Event_DeleteFile
	FileBank_FileUpload        []Event_FileUpload
	FileBank_FileUpdate        []Event_FileUpdate
	FileBank_FileChangeState   []Event_FileChangeState
	FileBank_BuyFile           []Event_BuyFile
	FileBank_Purchased         []Event_Purchased
	FileBank_InsertFileSlice   []Event_InsertFileSlice
	FileBank_FillerUpload      []Event_FillerUpload
	FileBank_ClearInvalidFile  []Event_ClearInvalidFile
	FileBank_RecoverFile       []Event_RecoverFile
	FileBank_ReceiveSpace      []Event_ReceiveSpace
	FileBank_UploadDeclaration []Event_UploadDeclaration
	FileBank_CreateBucket      []Event_CreateBucket
	FileBank_DeleteBucket      []Event_DeleteBucket
	// StorageHandler
	StorageHandler_BuySpace             []Event_BuySpace
	StorageHandler_ExpansionSpace       []Event_ExpansionSpace
	StorageHandler_RenewalSpace         []Event_RenewalSpace
	StorageHandler_LeaseExpired         []Event_LeaseExpired
	StorageHandler_LeaseExpireIn24Hours []Event_LeaseExpireIn24Hours
	// TeeWorker
	TeeWorker_RegistrationScheduler []Event_RegistrationScheduler
	TeeWorker_UpdateScheduler       []Event_UpdateScheduler
	// OSS
	Oss_OssRegister []Event_OssRegister
	Oss_OssUpdate   []Event_OssUpdate
	// System
	types.EventRecords
}
