package node

import (
	"net/http"
	"strings"

	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/CESSProject/go-keyring"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mr-tron/base58"
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

// VerifyToken is used to parse and verify token
func (n *Node) verifySignature(account, message, signature string) ([]byte, error) {
	if account == "" || signature == "" {
		return nil, errors.New("no identity authentication information")
	}
	pkey, err := sutils.ParsingPublickey(account)
	if err != nil {
		return nil, err
	}

	ss58, err := sutils.EncodePublicKeyAsSubstrateAccount(pkey)
	if err != nil {
		return nil, err
	}

	verkr, _ := keyring.FromURI(ss58, keyring.NetSubstrate{})

	sign_bytes, err := base58.Decode(signature)
	if err != nil {
		if strings.Contains(err.Error(), "zero length") {
			return nil, errors.New("empty signature")
		}
		return nil, errors.New("signature not encoded with base58")
	}

	if len(sign_bytes) != 64 {
		return nil, errors.New("wrong signature length")
	}

	var sign_array [64]byte
	for i := 0; i < 64; i++ {
		sign_array[i] = sign_bytes[i]
	}

	// Verify signature
	ok := verkr.Verify(verkr.SigningContext([]byte(message)), sign_array)
	if ok {
		return pkey, nil
	}
	return nil, errors.New("signature verification failed")
}
