package token

import (
	"cess-gateway/configs"
	"cess-gateway/internal/encryption"
	"cess-gateway/tools"
	"encoding/json"
	"time"

	"github.com/btcsuite/btcutil/base58"
)

type TokenMsgType struct {
	UserId          int64  `json:"userId"`
	CreateUserTime  int64  `json:"createUserTime"`
	CreateTokenTime int64  `json:"createTokenTime"`
	ExpirationTime  int64  `json:"expirationTime"`
	Mailbox         string `json:"mailbox"`
	RandomCode      string `json:"randomCode"`
}

// Generate a new token
func GenerateNewToken(mailbox string) (string, error) {
	var (
		err   error
		token = TokenMsgType{}
	)
	token.UserId, err = tools.GetGuid(int64(tools.RandomInRange(0, 1023)))
	if err != nil {
		return "", err
	}
	token.RandomCode = tools.GetRandomcode(16)
	token.Mailbox = mailbox
	t := time.Now().Unix()
	token.CreateUserTime = t
	token.CreateTokenTime = t
	token.ExpirationTime = time.Unix(t, 0).Add(configs.ValidTimeOfToken).Unix()
	bytes, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	en, err := encryption.RSA_Encrypt(bytes)
	if err != nil {
		return "", err
	}

	return base58.Encode(en), nil
}

// refresh a old token
func RefreshToken(old TokenMsgType) (string, error) {
	var (
		err   error
		token = TokenMsgType{}
	)
	token.UserId = old.UserId
	token.CreateUserTime = old.CreateUserTime
	token.Mailbox = old.Mailbox
	t := time.Now().Unix()
	token.CreateTokenTime = t
	token.ExpirationTime = time.Unix(t, 0).Add(configs.ValidTimeOfToken).Unix()
	token.RandomCode = tools.GetRandomcode(16)
	bytes, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	en, err := encryption.RSA_Encrypt(bytes)
	if err != nil {
		return "", err
	}

	return base58.Encode(en), nil
}

// Decode user token
func DecryptToken(token string) ([]byte, error) {
	bytes, err := encryption.RSA_Decrypt(base58.Decode(token))
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
