package chain

import "github.com/centrifuge/go-substrate-rpc-client/v4/types"

// cess chain state
const (
	State_Sminer      = "Sminer"
	State_SegmentBook = "SegmentBook"
	State_FileBank    = "FileBank"
	State_FileMap     = "FileMap"
)

// cess chain module method
const (
	FileMap_FileMetaInfo      = "File"
	FileMap_SchedulerInfo     = "SchedulerMap"
	FileBank_UserSpaceList    = "UserSpaceList"
	FileBank_UserFilelist     = "UserHoldFileList"
	Sminer_PurchasedSpace     = "PurchasedSpace"
	FileBank_PurchasedPackage = "PurchasedPackage"
)

// cess chain Transaction name
const (
	ChainTx_FileBank_Upload            = "FileBank.upload"
	ChainTx_FileBank_DeleteFile        = "FileBank.delete_file"
	ChainTx_FileBank_UploadDeclaration = "FileBank.upload_declaration"
	ChainTx_FileBank_BuyPackage        = "FileBank.buy_package"
	ChainTx_FileBank_UpgradePackage    = "FileBank.upgrade_package"
	ChainTx_FileBank_RenewalPackage    = "FileBank.renewal_package"
)

const (
	ERR_Failed  = "Failed"
	ERR_Timeout = "Timeout"
	ERR_Empty   = "Empty"
)

type FileHash [64]types.U8
type FileBlockId [68]types.U8

// ---RegisterMsg
type RegisterMsg struct {
	Acc      types.Bytes `json:"acc"`
	Collrate types.U128  `json:"collrate"`
	Random   types.U32   `json:"random"`
}

// ---SchedulerInfo
type SchedulerInfo struct {
	Ip              Ipv4Type
	Stash_user      types.AccountID
	Controller_user types.AccountID
}

type Ipv4Type_Query struct {
	Placeholder types.U8 //
	Index       types.U8
	Value       [4]types.U8
	Port        types.U16
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

// ---FileMetaInfo
type FileMetaInfo struct {
	FileSize  types.U64
	Index     types.U32
	FileState types.Bytes
	Users     []types.AccountID
	Names     []types.Bytes
	ChunkInfo []ChunkInfo
}

type ChunkInfo struct {
	MinerId   types.U64
	ChunkSize types.U64
	BlockNum  types.U32
	ChunkId   FileBlockId
	MinerIp   Ipv4Type
	MinerAcc  types.AccountID
}

// ---UserInfo
type UserSpaceListInfo struct {
	Size     types.U128 `json:"size"`
	Deadline types.U32  `json:"deadline"`
}

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

type UserFileList struct {
	File_hash types.Bytes
	File_size types.U64
}
