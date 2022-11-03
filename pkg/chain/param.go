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

// cess chain state
const (
	state_FileBank    = "FileBank"
	state_FileMap     = "FileMap"
	state_Sminer      = "Sminer"
	state_SegmentBook = "SegmentBook"
	state_System      = "System"
)

// cess chain module method
const (
	// System
	system_Account = "Account"
	system_Events  = "Events"
	// Sminer
	sminer_AllMinerItems  = "AllMiner"
	sminer_MinerItems     = "MinerItems"
	sminer_SegInfo        = "SegInfo"
	sminer_PurchasedSpace = "PurchasedSpace"
	sminer_TotalSpace     = "AvailableSpace"
	// FileMap
	fileMap_FileMetaInfo  = "File"
	fileMap_SchedulerInfo = "SchedulerMap"
	fileMap_SchedulerPuk  = "SchedulerPuk"
	// FileBank
	fileBank_UserSpaceList    = "UserSpaceList"
	fileBank_PurchasedPackage = "PurchasedPackage"
	fileBank_UserFilelist     = "UserHoldFileList"
	fileBank_FileRecovery     = "FileRecovery"
	// SegmentBook
	segmentBook_UnVerifyProof = "UnVerifyProof"
)

// cess chain Transaction name
const (
	// FileBank
	tx_FileBank_Update             = "FileBank.update"
	tx_FileBank_Upload             = "FileBank.upload"
	tx_FileBank_UploadFiller       = "FileBank.upload_filler"
	tx_FileBank_ClearRecoveredFile = "FileBank.recover_file"
	// SegmentBook
	tx_SegmentBook_VerifyProof = "SegmentBook.verify_proof"
	// FileMap
	tx_FileMap_UpdateScheduler = "FileMap.update_scheduler"
	tx_FileMap_Add_schedule    = "FileMap.registration_scheduler"
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
