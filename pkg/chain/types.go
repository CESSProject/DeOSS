/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

// DOT is "." character
const DOT = "."

// Pallets
const (
	// OSS is a module about DeOSS
	OSS = "Oss"
	// FILEBANK is a module about data metadata, bucket info, etc.
	FILEBANK = "FileBank"
	// SMINER is a module about storage miners
	SMINER = "Sminer"
	// TEEWOEKER is a module about TEE
	TEEWORKER = "TeeWorker"
	// AUDIT is a module on data challenges
	AUDIT = "Audit"
	// SYSTEM is a module about the system
	SYSTEM = "System"
)

// Pallet's method
const (
	// OSS
	AUTHORITYLIST = "AuthorityList"
	// SMINER
	ALLMINER   = "AllMiner"
	MINERITEMS = "MinerItems"
	// TEEWORKER
	SCHEDULERMAP = "SchedulerMap"
	// FILEBANK
	FILE       = "File"
	FILELIST   = "UserHoldFileList"
	BUCKET     = "Bucket"
	BUCKETLIST = "UserBucketList"
	// SYSTEM
	ACCOUNT = "Account"
	EVENTS  = "Events"
)

// Extrinsics
const (
	// FILEBANK
	TX_FILEBANK_UPDATE    = FILEBANK + DOT + "update"
	TX_FILEBANK_UPLOAD    = FILEBANK + DOT + "upload"
	TX_FILEBANK_CRTBUCKET = FILEBANK + DOT + "create_bucket"
	TX_FILEBANK_DELBUCKET = FILEBANK + DOT + "delete_bucket"
	TX_FILEBANK_DELFILE   = FILEBANK + DOT + "delete_file"
	TX_FILEBANK_UPLOADDEC = FILEBANK + DOT + "upload_declaration"
	// OSS
	TX_OSS_REGISTER = OSS + DOT + "register"
	TX_OSS_UPDATE   = OSS + DOT + "update"
)

const (
	FILE_STATE_ACTIVE  = "active"
	FILE_STATE_PENDING = "pending"
)

const (
	MINER_STATE_POSITIVE = "positive"
	MINER_STATE_FROZEN   = "frozen"
	MINER_STATE_EXIT     = "exit"
)

const (
	ERR_Failed  = "failed"
	ERR_Timeout = "timeout"
	ERR_Empty   = "empty"
)

// error type
var (
	ERR_RPC_CONNECTION  = errors.New("rpc connection failed")
	ERR_RPC_IP_FORMAT   = errors.New("unsupported ip format")
	ERR_RPC_TIMEOUT     = errors.New("timeout")
	ERR_RPC_EMPTY_VALUE = errors.New("empty")
)

type FileHash [64]types.U8
type FileBlockId [68]types.U8

// storage miner info
type MinerInfo struct {
	PeerId      types.U64
	IncomeAcc   types.AccountID
	Ip          Ipv4Type
	Collaterals types.U128
	State       types.Bytes
	Power       types.U128
	Space       types.U128
	RewardInfo  RewardInfo
}

type RewardInfo struct {
	Total       types.U128
	Received    types.U128
	NotReceived types.U128
}

// cache storage miner
type Cache_MinerInfo struct {
	Peerid uint64 `json:"peerid"`
	Ip     string `json:"ip"`
}

// file meta info
type FileMetaInfo struct {
	Size       types.U64
	Index      types.U32
	State      types.Bytes
	UserBriefs []UserBrief
	//Names      []types.Bytes
	BlockInfo []BlockInfo
}

// file block info
type BlockInfo struct {
	MinerId   types.U64
	BlockSize types.U64
	BlockNum  types.U32
	BlockId   [68]types.U8
	MinerIp   Ipv4Type
	MinerAcc  types.AccountID
}

// filler meta info
type FillerMetaInfo struct {
	Size      types.U64
	Index     types.U32
	BlockNum  types.U32
	BlockSize types.U32
	ScanSize  types.U32
	Acc       types.AccountID
	Hash      [64]types.U8
}

// scheduler info
type SchedulerInfo struct {
	Ip             Ipv4Type
	StashUser      types.AccountID
	ControllerUser types.AccountID
}

type IpAddress struct {
	IPv4 Ipv4Type
	IPv6 Ipv6Type
}
type Ipv4Type struct {
	Index types.U8
	Value [4]types.U8
	Port  types.U16
}
type Ipv6Type struct {
	Index types.U8
	Value [8]types.U16
	Port  types.U16
}

// user space package Info
type SpacePackage struct {
	Space           types.U128
	Used_space      types.U128
	Remaining_space types.U128
	Tenancy         types.U32
	Package_type    types.U8
	Start           types.U32
	Deadline        types.U32
	State           types.Bytes
}

type BucketInfo struct {
	Total_capacity     types.U32
	Available_capacity types.U32
	Objects_num        types.U32
	Objects_list       []FileHash
	Authority          []types.AccountID
}

type UserBrief struct {
	User        types.AccountID
	File_name   types.Bytes
	Bucket_name types.Bytes
}
