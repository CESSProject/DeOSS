/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package chain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewChainClient(t *testing.T) {
	rpcAddr := "wss://testnet-rpc0.cess.cloud/ws/"
	secret := "swear theme bounce soccer hungry gesture hurdle asset typical call balcony wrist"
	time := time.Duration(time.Second * time.Duration(20))
	_, err := NewChainClient(rpcAddr, secret, time)
	assert.NoError(t, err)
}
