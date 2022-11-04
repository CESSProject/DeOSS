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
	"github.com/CESSProject/cess-oss/configs"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type NewBucketType struct {
	Account   string
	Message   string
	Signature []byte
}

// It is used to authorize users
func (n *Node) newBucketHandle(c *gin.Context) {
	var (
		err error
		req AuthType
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

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})

	if !token.Valid {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet
				c.JSON(403, "TokenExpired")
				return
			}
		}
		c.JSON(403, "NoPermission")
		return
	}

	if err = c.ShouldBind(&req); err != nil {
		c.JSON(400, "Invalid.Body")
		return
	}
}
