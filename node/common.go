/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/CESSProject/go-keyring"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/vedhavyas/go-subkey/v2/sr25519"
)

func CheckPermissionsMdl(account string, accessmode string, blacklist, accounts []string) bool {
	for _, v := range blacklist {
		if v == account {
			return true
		}
	}
	switch accessmode {
	case configs.Access_Public:
		for _, v := range accounts {
			if v == account {
				return false
			}
		}
		return true
	case configs.Access_Private:
		for _, v := range accounts {
			if v == account {
				return true
			}
		}
		return false
	}
	return false
}

func VerifySignatureMdl(c *gin.Context) (string, []byte, bool) {
	account := c.Request.Header.Get(HTTPHeader_Account)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)
	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)

	timestamp, err := strconv.ParseInt(message, 10, 64)
	if err != nil {
		t, err := time.Parse(time.DateTime, message)
		if err == nil {
			if time.Now().After(t) {
				return account, nil, false
			}
		}
	} else {
		if isUnixTimestamp(timestamp) {
			if time.Now().Unix() >= timestamp {
				return account, nil, false
			}
		} else if isUnixMillTimestamp(timestamp) {
			if time.Now().UnixMilli() >= timestamp {
				return account, nil, false
			}
		}
	}

	if ethAccount != "" {
		ethAccInSian, err := VerifyEthSign(message, signature)
		if err != nil {
			return account, nil, false
		}
		if ethAccInSian != ethAccount {
			return account, nil, false
		}
		pkey, err := sutils.ParsingPublickey(account)
		if err != nil {
			return account, nil, false
		}
		return account, pkey, true
	}
	pkey, ok, err := utils.VerifySR25519WithPubkey(account, message, signature)
	if err != nil || !ok {
		pkey, ok, err = utils.VerifyPolkadotjsHexSign(account, message, signature)
		return account, pkey, ok
	}
	return account, pkey, ok
}

func CheckChainSt(cli chain.Chainer, c *gin.Context) error {
	syncSt, err := cli.SystemSyncState()
	if err != nil {
		ReturnJSON(c, 403, ERR_RPCConnection, nil)
		return err
	}

	if syncSt.CurrentBlock+5 < syncSt.HighestBlock {
		ReturnJSON(c, 403, ERR_RPCSyncing, nil)
		return err
	}
	return nil
}

func CheckAuthorize(cli chain.Chainer, c *gin.Context, pkey []byte) error {
	authAccs, err := cli.QueryAuthorityList(pkey, -1)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			ReturnJSON(c, 403, ERR_SpaceNotAuth, nil)
			return err
		}
		ReturnJSON(c, 403, ERR_RPCConnection, nil)
		return err
	}
	flag := false
	for _, v := range authAccs {
		if sutils.CompareSlice(cli.GetSignatureAccPulickey(), v[:]) {
			flag = true
			break
		}
	}
	if !flag {
		ReturnJSON(c, 403, fmt.Sprintf("please authorize the gateway account: %s", cli.GetSignatureAcc()), nil)
		return fmt.Errorf("please authorize the gateway account: %s", cli.GetSignatureAcc())
	}
	return nil
}

func CheckTerritory(cli chain.Chainer, c *gin.Context, pkey []byte, territoryName string) (uint64, error) {
	territoryInfo, err := cli.QueryTerritory(pkey, territoryName, -1)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			ReturnJSON(c, 400, ERR_NoTerritory, nil)
			return 0, err
		}
		ReturnJSON(c, 403, ERR_RPCConnection, nil)
		return 0, err
	}

	blockheight, err := cli.QueryBlockNumber("")
	if err != nil {
		ReturnJSON(c, 403, ERR_RPCConnection, nil)
		return 0, err
	}

	if uint32(territoryInfo.Deadline) < blockheight {
		ReturnJSON(c, 400, ERR_TerritoryExpiresSoon, nil)
		return 0, fmt.Errorf("territory expired: %d < %d", territoryInfo.Deadline, blockheight)
	}

	remainingSpace, err := strconv.ParseUint(territoryInfo.RemainingSpace.String(), 10, 64)
	if err != nil {
		ReturnJSON(c, 500, ERR_SystemErr, nil)
		return 0, err
	}

	return remainingSpace, nil
}

// string: tmp dir
// string: tmp file path
// error: error
func CreateTmpPath(c *gin.Context, dir, account string) (string, string, error) {
	var (
		err      error
		cacheDir string
		uid      uuid.UUID
	)
	for {
		uid, err = uuid.NewUUID()
		if err != nil {
			time.Sleep(time.Millisecond * 10)
			continue
		}

		cacheDir = filepath.Join(dir, account, uid.String())
		_, err = os.Stat(cacheDir)
		if err != nil {
			err = os.MkdirAll(cacheDir, 0755)
			if err != nil {
				ReturnJSON(c, 403, ERR_SystemErr, nil)
				return "", "", err
			}
			return cacheDir, filepath.Join(cacheDir, fmt.Sprintf("%v", time.Now().Unix())), nil
		}
		time.Sleep(time.Second)
		continue
	}
}

func (n *Node) VerifyAccountSignature(account, msg, signature string) ([]byte, error) {
	var err error
	var publicKey []byte

	if account == "" {
		return nil, errors.New("Account is missing in request header")
	}
	if msg == "" {
		return nil, errors.New("Message is missing in request header")
	}
	if signature == "" {
		return nil, errors.New("Signature is missing in request header")
	}
	publicKey, err = n.verifySignature(account, msg, signature)
	if err == nil {
		return publicKey, nil
	}
	publicKey, err = n.verifySR25519Signature(account, msg, signature)
	if err == nil {
		return publicKey, nil
	}
	publicKey, err = n.verifyJsSignatureHex(account, msg, signature)
	if err == nil {
		return publicKey, nil
	}
	publicKey, err = n.verifyJsSignatureBase58(account, msg, signature)
	if err != nil {
		return nil, errors.New("Signature verification failed")
	}
	return publicKey, nil
}

func VerifyEthSign(message string, sign string) (string, error) {
	// Hash the unsigned message using EIP-191
	hashedMessage := []byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message)) + message)
	hash := crypto.Keccak256Hash(hashedMessage)

	// Get the bytes of the signed message
	decodedMessage, err := hexutil.Decode(sign)
	if err != nil {
		return "", err
	}

	// Handles cases where EIP-115 is not implemented (most wallets don't implement it)
	if decodedMessage[64] == 27 || decodedMessage[64] == 28 {
		decodedMessage[64] -= 27
	}

	// Recover a public key from the signed message
	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), decodedMessage)
	if sigPublicKeyECDSA == nil {
		err = errors.New("Could not get a public get from the message signature")
	}
	if err != nil {
		return "", err
	}

	return crypto.PubkeyToAddress(*sigPublicKeyECDSA).String(), nil
}

// VerifyToken is used to parse and verify token
func (n *Node) verifySignature(account, message, signature string) ([]byte, error) {
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
	pkey, err = n.verifyJsSignatureBase58(account, message, signature)
	if err == nil {
		return pkey, nil
	}
	pkey, err = n.verifyJsSignatureHex(account, message, signature)
	if err == nil {
		return pkey, nil
	}
	return nil, errors.New("signature verification failed")
}

// VerifyToken is used to parse and verify token
func (n *Node) verifyJsSignatureBase58(account, message, signature string) ([]byte, error) {
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

	if strings.HasPrefix(message, "<Bytes>") && strings.HasSuffix(message, "</Bytes>") {
		ok := verkr.Verify(verkr.SigningContext([]byte(message)), sign_array)
		if ok {
			return pkey, nil
		}
	}

	// Verify signature
	ok := verkr.Verify(verkr.SigningContext([]byte("<Bytes>"+message+"</Bytes>")), sign_array)
	if ok {
		return pkey, nil
	}
	return nil, errors.New("signature verification failed")
}

// VerifyToken is used to parse and verify token
func (n *Node) verifyJsSignatureHex(account, message, signature string) ([]byte, error) {
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

	sign_bytes, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		return nil, err
	}

	if len(sign_bytes) != 64 {
		return nil, errors.New("wrong signature length")
	}

	var sign_array [64]byte
	for i := 0; i < 64; i++ {
		sign_array[i] = sign_bytes[i]
	}

	// Verify signature
	if strings.HasPrefix(message, "<Bytes>") && strings.HasSuffix(message, "</Bytes>") {
		ok := verkr.Verify(verkr.SigningContext([]byte(message)), sign_array)
		if ok {
			return pkey, nil
		}
	}

	ok := verkr.Verify(verkr.SigningContext([]byte("<Bytes>"+message+"</Bytes>")), sign_array)
	if ok {
		return pkey, nil
	}
	return nil, errors.New("signature verification failed")
}

// VerifyToken is used to parse and verify token
func (n *Node) verifySR25519Signature(account, message, signature string) ([]byte, error) {
	if account == "" || signature == "" {
		return nil, errors.New("no identity authentication information")
	}

	pkey, err := sutils.ParsingPublickey(account)
	if err != nil {
		return nil, err
	}

	pub, err := sr25519.Scheme{}.FromPublicKey(pkey)
	if err != nil {
		return pkey, err
	}
	sign_bytes, err := base58.Decode(signature)
	if err != nil {
		return pkey, err
	}
	ok := pub.Verify([]byte("<Bytes>"+message+"</Bytes>"), sign_bytes)
	if !ok {
		return pkey, errors.New("signature verification failed")
	}
	return pkey, nil
}

func (n *Node) AccessControl(account string) error {
	if account == "" {
		return errors.New("missing account in header")
	}

	err := sutils.VerityAddress(account, sutils.CessPrefix)
	if err != nil {
		return fmt.Errorf("%s is not a CESS account, no permissions", account)
	}

	bwlist := n.Config.Access.Account
	var flag bool
	switch n.Config.Access.Mode {
	case configs.Access_Public:
		for _, v := range bwlist {
			if v == account {
				for _, vv := range n.Config.User.Account {
					if account == vv {
						flag = true
						break
					}
				}
				if !flag {
					return fmt.Errorf("your account [%s] does not have permissions", account)
				}
			}
		}
		return nil
	case configs.Access_Private:
		for _, v := range bwlist {
			if v == account {
				return nil
			}
		}
		for _, v := range n.Config.User.Account {
			if v == account {
				return nil
			}
		}
	}
	return fmt.Errorf("your account [%s] does not have permissions", account)
}
