/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package chain

// Pallets
const (
	pallet_FileBank    = "FileBank"
	pallet_FileMap     = "FileMap"
	pallet_Sminer      = "Sminer"
	pallet_SegmentBook = "SegmentBook"
	pallet_System      = "System"
	pallet_Oss         = "Oss"
)

// Pallet's method
const (
	// System
	account = "Account"
	events  = "Events"

	// Sminer
	allMinerItems = "AllMiner"
	minerItems    = "MinerItems"
	segInfo       = "SegInfo"

	// FileMap
	fileMetaInfo = "File"
	schedulerMap = "SchedulerMap"

	// FileBank
	fileBank_UserFilelist = "UserHoldFileList"
	fileBank_Bucket       = "Bucket"
	fileBank_BucketList   = "UserBucketList"
	// Oss
	oss     = "Oss"
	Grantor = "AuthorityList"
)

// Extrinsics
const (
	// FileBank
	tx_FileBank_Update         = "FileBank.update"
	tx_FileBank_Upload         = "FileBank.upload"
	FileBank_CreateBucket      = "FileBank.create_bucket"
	FileBank_DeleteBucket      = "FileBank.delete_bucket"
	FileBank_DeleteFile        = "FileBank.delete_file"
	FileBank_UploadDeclaration = "FileBank.upload_declaration"
	// SegmentBook
	tx_SegmentBook_VerifyProof = "SegmentBook.verify_proof"
	// Oss
	OssRegister = "Oss.register"
	OssUpdate   = "Oss.update"
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
