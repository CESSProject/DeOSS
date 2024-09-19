/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package confile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_NewConfig(t *testing.T) {
	confile := "./conf_test.yaml"
	_, err := NewConfig(confile)
	assert.NoError(t, err)
}
