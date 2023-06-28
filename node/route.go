/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import "fmt"

func (n *Node) addRoute() {
	n.Engine.POST("/auth", n.authHandle)

	n.Engine.GET(fmt.Sprintf("/:%s", HTTP_ParameterName), n.getHandle)

	n.Engine.PUT("/", n.putHandle)

	n.Engine.DELETE(fmt.Sprintf("/:%s", HTTP_ParameterName), n.delHandle)

	n.Engine.DELETE("/", n.delFilesHandle)
}
