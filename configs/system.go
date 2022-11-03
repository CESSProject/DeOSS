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

import (
	"time"
)

// system
const (
	// name
	Name = "cess-oss"
	// version
	Version = Name + " " + "v0.1.0"
	// description
	Description = "Implementation of object storage service based on cess platform"
)

const (
	// base dir
	BaseDir = "/usr/local/cess-gateway"

	// log file dir
	LogfileDir = BaseDir + "/log"

	// keyfile dir
	PrivateKeyfile = BaseDir + "/.privateKey.pem"
	PublicKeyfile  = BaseDir + "/.publicKey.pem"

	// database dir
	DbDir = BaseDir + "/db"

	// file cache dir
	FileCacheDir = BaseDir + "/cache"

	// file records dir
	FilRecordsDir = "records"

	// random number valid time, the unit is minutes
	RandomValidTime = 5.0

	// the time to wait for the event, in seconds
	TimeToWaitEvents = time.Duration(time.Second * 15)

	// The validity period of the token, the default is 30 days
	ValidTimeOfToken = time.Duration(time.Hour * 24 * 30)

	// Valid Time Of Captcha
	ValidTimeOfCaptcha = time.Duration(time.Minute * 5)

	//
	SIZE_1KB = 1024
	SIZE_1MB = 1024 * SIZE_1KB
	SIZE_1GB = 1024 * SIZE_1MB
)

const (
	//Scheduler's rpc service name
	RpcService_Scheduler = "wservice"
	//Scheduler's rpc service name
	RpcService_Miner = "mservice"
	//auth method of rpc service
	RpcMethod_auth = "auth"
	//write method of rpc service
	RpcMethod_WriteFile = "writefile"
	//read method of rpc service
	RpcMethod_ReadFile = "readfile"
	//
	RpcBuffer = 1024 * 1024

	//
	EmailSubject_captcha = "CESS | Authorization captcha"
	EmailSubject_token   = "CESS | Authorization token"
)

const (
	HELP_common = `Please check with the following help information:
    1.Check if the wallet balance is sufficient
    2.Block hash:`
	HELP_BuySpace1 = `Please check with the following help information:
    1.Check whether the available space is sufficient
    2.Check if the wallet balance is sufficient
    3.Block hash:`
	HELP_BuySpace2 = `    4.Check the fileBank.buyPackage transaction event result in the block hash above:
        If system.ExtrinsicFailed is prompted, it means failure;
        If system.ExtrinsicSuccess is prompted, it means success;`
	HELP_Upgrade = `    3.Check the fileBank.upgradePackage transaction event result in the block hash above:
        If system.ExtrinsicFailed is prompted, it means failure;
        If system.ExtrinsicSuccess is prompted, it means success;`
	HELP_Renewal = `    3.Check the fileBank.renewalPackage transaction event result in the block hash above:
        If system.ExtrinsicFailed is prompted, it means failure;
        If system.ExtrinsicSuccess is prompted, it means success;`
)

// return state code
const (
	Code_200 = 200
	Code_400 = 400
	Code_403 = 403
	Code_404 = 404
	Code_500 = 500
	Code_600 = 600
)

var PublicKey []byte
