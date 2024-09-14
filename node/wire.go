//go:build wireinject

/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import "github.com/google/wire"

func InitNode() *Node {
	wire.Build()
	return &Node{}
}
