/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

func (n *Node) addRoute() {
	n.Engine.POST("/auth", n.authHandle)

	n.Engine.PUT("/:name", n.putHandle)

	n.Engine.DELETE("/:name", n.delHandle)

	n.Engine.GET("/:name", n.GetHandle)
}
