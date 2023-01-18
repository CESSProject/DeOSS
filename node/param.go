/*
   Copyright 2022 CESS (Cumulus Encrypted Storage System) authors

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

package node

type RespMsg struct {
	Code int
	Err  error
}

const (
	ERR_RETRY = "RETRY"
)

const (
	Header_Auth       = "Authorization"
	Header_BucketName = "BucketName"
	Header_Account    = "Account"
	Header_Digest     = "Digest"
	Header_Operation  = "Operation"
	TokenDated        = 60 * 60 * 24 * 30
)

const (
	Opt_View     = "view"
	Opt_Download = "download"
	Opt_Account  = "account"
)

const (
	Key_Digest        = "digest:"
	Key_Slices        = "slices:"
	Key_StoreProgress = "progress"
)

const (
	PUT_ParameterName = "name"
	FormFileKey1      = "file"
	FormFileKey2      = "File"
	FormFileKey3      = "FILE"
)

const (
	ERR_ReportProblem = "Sorry, please report this problem to the service provider:"

	INFO_PutRequest       = "PutRequest"
	ERR_MissToken         = "InvalidHead.MissToken"
	ERR_EmptySeed         = "InvalidProfile.EmptySeed"
	ERR_NoPermission      = "InvalidToken.NoPermission"
	ERR_InvalidToken      = "InvalidHead.Token"
	ERR_InvalidName       = "InvalidParameter.Name"
	ERR_InvalidBucketName = "InvalidHead.BucketName"
	ERR_UnauthorizedSpace = "UnauthorizedSpace"
	ERR_EmptyFile         = "InvalidBody.EmptyFile"
	ERR_DuplicateFileName = "InvalidParameter.DuplicateFileName"
	ERR_InternalServer    = "InternalError"
)

const (
	Cach_Hash256 = "hash256:"
)
