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

package configs

import "time"

// account
const (
	// CESS token precision
	CESSTokenPrecision = 1_000_000_000_000
	// MinimumBalance is the minimum balance required for the program to run
	// The unit is pico
	MinimumBalance = 2 * CESSTokenPrecision
)

// byte size
const (
	SIZE_1KiB = 1024
	SIZE_1MiB = 1024 * SIZE_1KiB
	SIZE_1GiB = 1024 * SIZE_1MiB
)

// http
const (
	Header_Auth       = "Authorization"
	Header_BucketName = "BucketName"
	Header_Account    = "Account"
	Header_Operation  = "Operation"
	TokenDated        = 60 * 60 * 24 * 30
)

const (
	// Tcp message interval
	TCP_Message_Interval = time.Duration(time.Millisecond * 10)
	// Number of tcp message caches
	TCP_Message_Send_Buffers = 10
	TCP_Message_Read_Buffers = 10
	//
	TCP_SendBuffer = 8192
	TCP_ReadBuffer = 12000
	//
	Tcp_Dial_Timeout = time.Duration(time.Second * 5)
)

const (
	// Time out waiting for transaction completion
	TimeOut_WaitBlock = time.Duration(time.Second * 15)
)

// explanation
const (
	HELP_common = `Please check with the following help information:
    1.Check if the wallet balance is sufficient
    2.Block hash:`
	HELP_register = `    3.Check the FileMap.OssRegister transaction event result in the block hash above:
        If system.ExtrinsicFailed is prompted, it means failure;
        If system.ExtrinsicSuccess is prompted, it means success;`
	HELP_update = `    3.Check the FileMap.OssUpdate transaction event result in the block hash above:
        If system.ExtrinsicFailed is prompted, it means failure;
        If system.ExtrinsicSuccess is prompted, it means success;`
)

// log file
var (
	LogFiles = []string{
		"common",   //General log
		"upfile",   //Upload file log
		"panic",    //Panic log
		"downfile", //Download log
	}
)
