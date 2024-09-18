/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import "github.com/gin-gonic/gin"

type RespType struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

func ReturnJSON(c *gin.Context, code int, msg string, data any) {
	c.JSON(200, RespType{
		Code: code,
		Msg:  msg,
		Data: data,
	})
}
