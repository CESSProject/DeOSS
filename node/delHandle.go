/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"net/http"
	"unsafe"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/chain"
	"github.com/CESSProject/DeOSS/pkg/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// delHandle is used to delete buckets or files
func (n *Node) delHandle(c *gin.Context) {
	var (
		err    error
		acc    string
		txHash string
	)

	// token
	tokenString := c.Request.Header.Get(configs.Header_Auth)
	if tokenString == "" {
		c.JSON(400, "InvalidHead.MissToken")
		return
	}

	signKey, err := utils.CalcMD5(n.Confile.GetCtrlPrk())
	if err != nil {
		c.JSON(500, "InternalError")
		return
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return signKey, nil
		})

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		acc = claims.Account
	} else {
		c.JSON(403, "NoPermission")
		return
	}

	pkey, err := utils.DecodePublicKeyOfCessAccount(acc)
	if err != nil {
		c.JSON(400, "InvalidHead.Token")
		return
	}

	deleteName := c.Param("name")
	if len(deleteName) == int(unsafe.Sizeof(chain.FileHash{})) {
		txHash, err = n.Chain.DeleteFile(pkey, deleteName)
		if err != nil {
			c.JSON(400, err.Error())
			return
		}
	} else if VerifyBucketName(deleteName) {
		txHash, err = n.Chain.DeleteBucket(pkey, deleteName)
		if err != nil {
			c.JSON(400, err.Error())
			return
		}
	} else {
		c.JSON(400, "InvalidParameter.Name")
		return
	}

	c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
}
