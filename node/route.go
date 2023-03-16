/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

func (n *Node) addRoute() {
	n.Handle.POST("/auth", n.authHandle)

	n.Handle.PUT("/:name", n.putHandle)

	n.Handle.DELETE("/:name", n.delHandle)

	n.Handle.GET("/:name", n.GetHandle)
}
