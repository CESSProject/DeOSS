package node

import (
	"net/http"

	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// VerifyToken is used to parse and verify token
func (n *Node) verifyToken(token string, respmsg *RespMsg) (string, []byte, error) {
	var (
		ok       bool
		err      error
		claims   *CustomClaims
		jwttoken *jwt.Token
		account  string
	)

	if respmsg.Err != nil {
		return account, nil, err
	}

	if token == "" {
		respmsg.Code = http.StatusForbidden
		respmsg.Err = errors.New(ERR_Authorization)
		return account, nil, respmsg.Err
	}

	// parse token
	jwttoken, err = jwt.ParseWithClaims(
		token,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return n.signkey, nil
		})

	if claims, ok = jwttoken.Claims.(*CustomClaims); ok && jwttoken.Valid {
		account = claims.Account
	} else {
		respmsg.Code = http.StatusForbidden
		respmsg.Err = errors.New(ERR_NoPermission)
		return account, nil, err
	}
	pkey, err := sutils.ParsingPublickey(account)
	if err != nil {
		respmsg.Code = http.StatusBadRequest
		respmsg.Err = errors.New(ERR_InvalidToken)
		return account, nil, err
	}

	respmsg.Code = http.StatusOK
	respmsg.Err = nil
	return account, pkey, nil
}
