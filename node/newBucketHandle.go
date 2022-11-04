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
	"regexp"
	"strings"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type NewBucketType struct {
	BucketName string `json:"bucket_name"`
}

// It is used to authorize users
func (n *Node) newBucketHandle(c *gin.Context) {
	var (
		err error
		req NewBucketType
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

	if !VerifyBucketName(req.BucketName) {
		c.JSON(400, "InvalidParameter.BucketName")
		return
	}
}

// Bucket name verification rules
// It can only contain numbers, lowercase letters, special characters (. -)
// And the length is 3-63
// Must start and end with a letter or number
// Must not contain two adjacent points
// Must not be formatted as an IP address
func VerifyBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}

	re, err := regexp.Compile(`^[a-z0-9.-]{3,63}$`)
	if err != nil {
		return false
	}

	if !re.MatchString(name) {
		return false
	}

	if strings.Contains(name, "..") {
		return false
	}

	if byte(name[0]) == byte('.') ||
		byte(name[0]) == byte('-') ||
		byte(name[len(name)-1]) == byte('.') ||
		byte(name[len(name)-1]) == byte('-') {
		return false
	}

	return !utils.IsIPv4(name)
}
