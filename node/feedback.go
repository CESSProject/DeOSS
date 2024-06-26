/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func (n *Node) FeedbackLog(c *gin.Context) {
	var fpath string
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}
	formfile, fileHeder, err := c.Request.FormFile("file")
	if err != nil {
		return
	}
	account := c.Request.Header.Get(HTTPHeader_Account)
	fpath = filepath.Join(n.fadebackDir, account+fileHeder.Filename)
	f, err := os.Create(fpath)
	if err != nil {
		n.Log("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}

	_, err = io.Copy(f, formfile)
	if err != nil {
		f.Close()
		n.Log("err", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusInternalServerError, ERR_InternalServer)
		return
	}
	f.Close()
	c.JSON(http.StatusOK, nil)
}
