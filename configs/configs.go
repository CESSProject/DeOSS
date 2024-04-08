/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package configs

import "time"

// account
const (
	// CESS token precision
	CESSTokenPrecision = 1_000_000_000_000_000_000
	// MinimumBalance is the minimum balance required for the program to run
	// The unit is pico
	MinimumBalance = 2 * CESSTokenPrecision
)

// http
const (
	Header_Auth       = "Authorization"
	Header_BucketName = "BucketName"
	Header_Account    = "Account"
	Header_Operation  = "Operation"
)

const FileCacheExpirationTime = 720

const MaxTrackThread = 10

// Time out waiting for transaction completion
const TimeOut_WaitBlock = time.Duration(time.Second * 30)

const DefaultConfig = "conf.yaml"

const (
	Access_Public  = "public"
	Access_Private = "private"
)
