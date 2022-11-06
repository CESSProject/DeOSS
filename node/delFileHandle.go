/*
   Copyright 2022 CESS scheduler authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package node

import (
	"net/http"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type DelFileType struct {
	FileHash string `json:"file_hash"`
}

// It is used to authorize users
func (n *Node) delFileHandle(c *gin.Context) {
	var (
		err error
		acc string
		req DelFileType
	)

	// token
	tokenString := c.Request.Header.Get(configs.Header_Auth)
	if tokenString == "" {
		//Uld.Sugar().Infof("[%v] head missing token", c.ClientIP())
		c.JSON(403, "NoPermission")
		return
	}

	mySigningKey, err := n.Cache.Get([]byte("SigningKey"))
	if err != nil {
		c.JSON(400, "InternalError")
		return
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return mySigningKey, nil
		})

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		acc = claims.Account
	} else {
		c.JSON(403, "NoPermission")
		return
	}

	pkey, err := utils.DecodePublicKeyOfCessAccount(acc)
	if err != nil {
		c.JSON(400, "InvalidParameter.Token")
		return
	}
	txHash, err := n.Chain.DeleteFile(pkey, req.FileHash)
	if err != nil {
		c.JSON(400, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]string{"Block hash:": txHash})
}
