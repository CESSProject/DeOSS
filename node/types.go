/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

// HTTP HEADER
const (
	HTTPHeader_Authorization = "Authorization"
	HTTPHeader_BucketName    = "BucketName"
	HTTPHeader_Account       = "Account"
	HTTPHeader_Digest        = "Digest"
	HTTPHeader_Operation     = "Operation"
	HTTPHeader_Message       = "Message"
	HTTPHeader_Signature     = "Signature"
	HTTPHeader_Fid           = "Fid"
	HTTPHeader_Cipher        = "cipher"
)

const (
	Active = iota
	Calculate
	Missing
	Recovery
)

const (
	HTTP_ParameterName = "name"
	FormFileKey1       = "file"
	FormFileKey2       = "File"
	FormFileKey3       = "FILE"
)

const TokenDated = 60 * 60 * 24 * 30
const MaxMemUsed = 512 << 20

const (
	//ERR_ReportProblem = "Sorry, please report this problem to the service provider:"

	INFO_PutRequest         = "PutRequest"
	INFO_PostRestoreRequest = "PostRestoreRequest"
	INFO_GetRequest         = "GetRequest"
	INFO_GetRestoreRequest  = "GetRestoreRequest"
	INFO_DelRequest         = "DelRequest"

	ERR_DuplicateOrder        = "duplicate order"
	ERR_MissToken             = "InvalidHead.MissToken"
	ERR_EmptySeed             = "InvalidProfile.EmptySeed"
	ERR_MissingAccount        = "InvalidHead.MissingAccount"
	ERR_InvalidAccount        = "InvalidHead.Account"
	ERR_NoPermission          = "InvalidToken.NoPermission"
	ERR_InvalidToken          = "InvalidHead.Token"
	ERR_InvalidName           = "InvalidParameter.Name"
	ERR_InvalidFilehash       = "InvalidParameter.FileHash"
	ERR_InvalidParaBucketName = "InvalidParameter.BucketName"
	ERR_InvalidBucketName     = "InvalidHead.BucketName"
	ERR_EmptyBucketName       = "Invalid.EmptyBucketName"
	ERR_UnauthorizedSpace     = "UnauthorizedSpace"
	ERR_EmptyFile             = "InvalidBody.EmptyFile"
	ERR_ReadBody              = "InvalidBody.ReadErr"
	ERR_ParseBody             = "InvalidBody.ParseErr"
	//ERR_SpaceExpired          = "space expired"
	ERR_NotEnoughSpace = "not enough account space"

	ERR_InternalServer  = "InternalError"
	ERR_FileNameTooLang = "The file name length cannot exceed 63 characters"
	ERR_NoSpace         = "please purchase space first"
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

	ERR_AccountNotExist   = "account does not exist"
	ERR_RpcFailed         = "rpc connection failed"
	ERR_SpaceExpiresSoon  = "space expires soon"
	ERR_SpaceNotAuth      = "space is not authorized"
	ERR_DeviceSpaceNoLeft = "no space left on the server device"

	ERR_SysMemNoLeft = "server unsupported file size"

	ERR_ReceiveFile = "InternalError"
)

const (
	Cache_SyncBlock       = "syncblock"
	Cache_UserFiles       = "userfiles:"
	Cache_UserDeleteFiles = "userdeletefiles:"
	Cache_WantFiles       = "wantfiles:"
)
