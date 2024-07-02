/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"net/http"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/gin-gonic/gin"
)

// getHandle
func (n *Node) Get_version(c *gin.Context) {
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}
	n.Logget("info", clientIp+" get version: "+configs.Version)
	c.JSON(http.StatusOK, configs.Version)
}
