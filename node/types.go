package node

type RespMsg struct {
	Code int
	Err  error
}

const (
	Header_Auth       = "Authorization"
	Header_BucketName = "BucketName"
	Header_Account    = "Account"
	Header_Digest     = "Digest"
	Header_Operation  = "Operation"
	TokenDated        = 60 * 60 * 24 * 30
)

const (
	Active = iota
	Calculate
	Missing
	Recovery
)

const (
	PUT_ParameterName = "name"
	FormFileKey1      = "file"
	FormFileKey2      = "File"
	FormFileKey3      = "FILE"
)

const (
	ERR_ReportProblem = "Sorry, please report this problem to the service provider:"

	INFO_PutRequest = "PutRequest"
	INFO_GetRequest = "GetRequest"

	ERR_MissToken         = "InvalidHead.MissToken"
	ERR_EmptySeed         = "InvalidProfile.EmptySeed"
	ERR_NoPermission      = "InvalidToken.NoPermission"
	ERR_InvalidToken      = "InvalidHead.Token"
	ERR_InvalidName       = "InvalidParameter.Name"
	ERR_InvalidBucketName = "InvalidHead.BucketName"
	ERR_EmptyBucketName   = "Invalid.EmptyBucketName"
	ERR_UnauthorizedSpace = "UnauthorizedSpace"
	ERR_EmptyFile         = "InvalidBody.EmptyFile"
	ERR_DuplicateFileName = "InvalidParameter.DuplicateFileName"
	ERR_ReadBody          = "InvalidBody.ReadErr"
	ERR_InternalServer    = "InternalError"
)
