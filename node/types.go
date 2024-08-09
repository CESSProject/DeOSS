/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"github.com/CESSProject/DeOSS/common/coordinate"
	"github.com/CESSProject/cess-go-sdk/chain"
)

type TrackerInfo struct {
	Segment       []chain.SegmentDataInfo `json:"segment"`
	Owner         []byte                  `json:"owner"`
	ShuntMiner    ShuntMiner              `json:"shunt_miner"`
	Points        coordinate.Range        `json:"range"`
	Fid           string                  `json:"fid"`
	FileName      string                  `json:"file_name"`
	BucketName    string                  `json:"bucket_name"`
	TerritoryName string                  `json:"territory_name"`
	CacheDir      string                  `json:"cache_dir"`
	Cipher        string                  `json:"cipher"`
	FileSize      uint64                  `json:"file_size"`
	PutFlag       bool                    `json:"put_flag"`
}

// old version
type RecordInfo struct {
	Segment       []chain.SegmentDataInfo `json:"segment"`
	Owner         []byte                  `json:"owner"`
	Fid           string                  `json:"fid"`
	FileName      string                  `json:"file_name"`
	BucketName    string                  `json:"bucket_name"`
	TerritoryName string                  `json:"territory_name"`
	CacheDir      string                  `json:"cache_dir"`
	Cipher        string                  `json:"cipher"`
	FileSize      uint64                  `json:"file_size"`
	PutFlag       bool                    `json:"put_flag"`
}

type ShuntMiner struct {
	Miners   []string `json:"miners"`
	Complete []bool   `json:"complete"`
}

// MinTrackerInfoLength = len(json.Marshal(TrackerInfo{}))
const MinTrackerInfoLength = 223

// HTTP HEADER
const (
	HTTPHeader_Bucket     = "Bucket"
	HTTPHeader_Territory  = "Territory"
	HTTPHeader_Account    = "Account"
	HTTPHeader_EthAccount = "EthAcc"
	HTTPHeader_Message    = "Message"
	HTTPHeader_Signature  = "Signature"
	HTTPHeader_Miner      = "Miner"
	HTTPHeader_Longitude  = "Longitude"
	HTTPHeader_Latitude   = "Latitude"
	HTTPHeader_Fid        = "Fid"
	HTTPHeader_Cipher     = "Cipher"
	HTTPHeader_BIdx       = "BlockIndex"
	HTTPHeader_BNum       = "BlockNumber"
	HTTPHeader_Fname      = "FileName"
	HTTPHeader_TSize      = "TotalSize"
	HTTPHeader_Format     = "Format"
)

const (
	Active = iota
	Calculate
	Missing
	Recovery
)

const (
	HTTP_ParameterName     = "name"
	HTTP_ParameterName_Fid = "fid"
)

const MaxMemUsed = 512 << 20

const (
	INFO_PutRequest         = "PutRequest"
	INFO_PostRestoreRequest = "PostRestoreRequest"
	INFO_GetRequest         = "GetRequest"
	INFO_GetRestoreRequest  = "GetRestoreRequest"
	INFO_DelRequest         = "DelRequest"

	ERR_DuplicateOrder             = "duplicate order"
	ERR_MissToken                  = "InvalidHead.MissToken"
	ERR_EmptySeed                  = "InvalidProfile.EmptySeed"
	ERR_MissingAccount             = "InvalidHead.MissingAccount"
	ERR_InvalidAccount             = "InvalidHead.Account"
	ERR_NoPermission               = "InvalidToken.NoPermission"
	ERR_InvalidToken               = "InvalidHead.Token"
	ERR_InvalidName                = "InvalidParameter.Name"
	ERR_InvalidFilehash            = "InvalidParameter.FileHash"
	ERR_InvalidParaBucketName      = "InvalidParameter.BucketName"
	ERR_InvalidBucketName          = "InvalidHead.BucketName"
	ERR_EmptyBucketName            = "Invalid.EmptyBucketName"
	ERR_UnauthorizedSpace          = "UnauthorizedSpace"
	ERR_EmptyFile                  = "InvalidBody.EmptyFile"
	ERR_EmptyBody                  = "InvalidBody.EmptyBody"
	ERR_ReadBody                   = "InvalidBody.ReadErr"
	ERR_ParseBody                  = "InvalidBody.ParseErr"
	ERR_NotEnoughSpace             = "not enough account space"
	ERR_InsufficientTerritorySpace = "insufficient territory space"

	ERR_InternalServer   = "InternalError"
	ERR_FileNameTooLang  = "The file name length cannot exceed 63 characters"
	ERR_FileNameTooShort = "The file name must be at least 3 characters long"
	ERR_NoSpace          = "please purchase space first"
	ERR_NoTerritory      = "please purchase territory first"
)

const (
	ERR_Authorization = "HeaderErr_Invalid_Authorization"

	ERR_HeadOperation = "HeaderErr_Invalid_Operation"

	ERR_NotFound  = "Not found"
	ERR_Forbidden = "no permission"

	ERR_BodyFormat         = "BodyErr_InvalidDataFormat"
	ERR_BodyFieldAccount   = "BodyErr_InvalidField_account"
	ERR_BodyFieldMessage   = "BodyErr_InvalidField_message"
	ERR_BodyFieldSignature = "BodyErr_InvalidField_signature"
	ERR_BodyEmptyFile      = "BodyErr_EmptyFile"

	ERR_HeaderFieldBucketName = "HeaderErr_InvalidBucketName"

	ERR_AccountNotExist      = "account does not exist"
	ERR_RpcFailed            = "rpc connection failed"
	ERR_SpaceExpiresSoon     = "space expires soon"
	ERR_TerritoryExpiresSoon = "territory expires soon"
	ERR_SpaceNotAuth         = "space is not authorized"
	ERR_DeviceSpaceNoLeft    = "no space left on the server device"

	ERR_SysMemNoLeft = "server unsupported file size"

	ERR_ReceiveFile = "InternalError"
)

const (
	Cache_SyncBlock       = "syncblock"
	Cache_UserFiles       = "userfiles:"
	Cache_UserDeleteFiles = "userdeletefiles:"
	Cache_WantFiles       = "wantfiles:"
)

type DuplicateType uint8

const (
	// not duplicate
	Duplicate0 DuplicateType = 0

	// not in file.owners
	Duplicate1 DuplicateType = 1

	// in file.owners
	Duplicate2 DuplicateType = 2
)
