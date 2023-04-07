/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package configs

import (
	"time"
)

// system
const (
	// name
	Name = "DeOSS"
	// Name space
	NameSpace = Name
	// version
	Version = Name + " " + "v0.1.2"
	// description
	Description = "Implementation of object storage service based on cess platform"
)

const (
	// base dir
	BaseDir = Name
	// log file dir
	Log = "log"
	// database dir
	Db = "db"
	// file dir
	File = "file"
	// tracked files
	Track = "track"
)

const (
	// BlockInterval is the time interval for generating blocks, in seconds
	BlockInterval = time.Second * time.Duration(6)
)
