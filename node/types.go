/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

// HTTP HEADER
const (
	HTTPHeader_Territory       = "Territory"
	HTTPHeader_Account         = "Account"
	HTTPHeader_EthAccount      = "EthAcc"
	HTTPHeader_Message         = "Message"
	HTTPHeader_Signature       = "Signature"
	HTTPHeader_Miner           = "Miner"
	HTTPHeader_Longitude       = "Longitude"
	HTTPHeader_Latitude        = "Latitude"
	HTTPHeader_Fid             = "Fid"
	HTTPHeader_Cipher          = "Cipher"
	HTTPHeader_Filename        = "Filename"
	HTTPHeader_Format          = "Format"
	HTTPHeader_Range           = "Content-Range"
	HTTPHeader_X_Forwarded_For = "X_Forwarded_For"
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

	ERR_InternalServer   = "Internal system error"
	ERR_FileNameTooLang  = "The file name length cannot exceed 63 characters"
	ERR_FileNameTooShort = "The file name must be at least 3 characters long"
	ERR_NoSpace          = "please purchase space first"
	ERR_NoTerritory      = "please purchase territory first"

	ERR_MissingContentRange = "Content-Range is missing from the request header"
	ERR_IllegalContentRange = "Illegal Content-Range content"
	ERR_FailedToRecvData    = "Failed to receive data"

	ERR_RPCConnection = "Failed to connect to rpc, please try again later."
	ERR_RPCSyncing    = "Syncing the latest blocks"
	ERR_EmptyFileName = "Empty file name"
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
	ERR_TerritoryExpiresSoon = "territory will expire soon"
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
