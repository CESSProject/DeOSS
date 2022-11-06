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
	Http_ReadTimeout  = 60
	Http_WriteTimeout = 60
	Http_MaximumHead  = SIZE_1MiB
	Header_Auth       = "Authorization"
	TokenDated        = 60 * 60 * 24 * 30
)

const (
	// Maximum number of connections in the miner's certification space
	MAX_TCP_CONNECTION uint8 = 3
	// Tcp client connection interval
	TCP_Connection_Interval = time.Duration(time.Millisecond * 100)
	// Tcp message interval
	TCP_Message_Interval = time.Duration(time.Millisecond * 20)
	// Tcp short message waiting time
	TCP_ShortMessage_WaitingTime = time.Duration(time.Second * 5)
	// Tcp short message waiting time
	TCP_FillerMessage_WaitingTime = time.Duration(time.Second * 180)
	// The slowest tcp transfers bytes per second
	TCP_Transmission_Slowest = SIZE_1KiB * 10
	// Number of tcp message caches
	TCP_Message_Send_Buffers = 32
	TCP_Message_Read_Buffers = 64
)

const (
	// Time out waiting for transaction completion
	TimeOut_WaitBlock = time.Duration(time.Second * 15)
	// Submit fillermeta interval
	SubmitFillermetaInterval = 60
	// The maximum number of proof results submitted in a transaction
	Max_SubProofResults = 40
)

// explanation
const (
	HELP_common = `Please check with the following help information:
    1.Check if the wallet balance is sufficient
    2.Block hash:`
	HELP_register = `    3.Check the FileMap.RegistrationScheduler transaction event result in the block hash above:
        If system.ExtrinsicFailed is prompted, it means failure;
        If system.ExtrinsicSuccess is prompted, it means success;`
	HELP_update = `    3.Check the FileMap.UpdateScheduler transaction event result in the block hash above:
        If system.ExtrinsicFailed is prompted, it means failure;
        If system.ExtrinsicSuccess is prompted, it means success;`
)

// log file
var (
	LogFiles = []string{
		"common",     //General log
		"upfile",     //Upload file log
		"panic",      //Panic log
		"verify",     //Verify proof log
		"minerCache", //Miner cache log
		"fillerMeta", //Submit filler meta log
		"genFiller",  //Generate filler log
		"speed",      //Record transmission time and speed
	}
)
