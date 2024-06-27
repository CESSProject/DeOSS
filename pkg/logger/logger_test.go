/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLogs(t *testing.T) {
	log_files := make(map[string]string, 2)
	log_files["log"] = "log.log"
	log_files["panic"] = "panic.log"
	_, err := NewLogs(log_files)
	assert.NoError(t, err)
}
