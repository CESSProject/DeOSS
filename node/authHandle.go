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
	"errors"
	"net/http"
	"time"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/utils"
	"github.com/CESSProject/go-keyring"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type CustomClaims struct {
	Account string `json:"account"`
	jwt.StandardClaims
}

type AuthType struct {
	Account   string
	Message   string
	Signature []byte
}

// It is used to authorize users
func (n *Node) authHandle(c *gin.Context) {
	var (
		err error
		req AuthType
	)
	if err = c.ShouldBind(&req); err != nil {
		c.JSON(400, "Invalid.Body")
		return
	}

	// Check publickey
	pubkey, err := utils.DecodePublicKeyOfCessAccount(req.Account)
	if err != nil {
		c.JSON(400, "InvalidParameter.Account")
		return
	}

	if req.Message == "" {
		c.JSON(400, "InvalidParameter.Message")
		return
	}

	if len(req.Signature) < 64 {
		c.JSON(400, "InvalidParameter.Signature")
		return
	}

	ok, err := VerifySign(pubkey, []byte(req.Message), req.Signature)
	if err != nil {
		c.JSON(400, err.Error())
		return
	}

	if !ok {
		c.JSON(403, "NoPermission")
		return
	}

	claims := CustomClaims{
		req.Account,
		jwt.StandardClaims{
			NotBefore: int64(time.Now().Unix() - 60),
			ExpiresAt: int64(time.Now().Unix() + int64(configs.TokenDated)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	mySigningKey, err := n.Cache.Get([]byte("SigningKey"))
	if err != nil {
		c.JSON(500, "InternalError")
		return
	}

	tokenString, err := token.SignedString(string(mySigningKey))
	if err != nil {
		c.JSON(500, "InternalError")
		return
	}

	c.JSON(http.StatusOK, map[string]string{"token": tokenString})
	return
}

func VerifySign(pkey, signmsg, sign []byte) (bool, error) {
	if len(signmsg) == 0 || len(sign) < 64 {
		return false, errors.New("Invalid signature")
	}

	ss58, err := utils.EncodePublicKeyAsSubstrateAccount(pkey)
	if err != nil {
		return false, err
	}

	verkr, _ := keyring.FromURI(ss58, keyring.NetSubstrate{})

	var sign_array [64]byte
	for i := 0; i < 64; i++ {
		sign_array[i] = sign[i]
	}

	// Verify signature
	return verkr.Verify(verkr.SigningContext(signmsg), sign_array), nil
}
