/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/CESSProject/DeOSS/configs"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/CESSProject/go-keyring"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/vedhavyas/go-subkey/v2/sr25519"
)

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

	switch n.Config.Access.Mode {
	case configs.Access_Public:
		for _, v := range bwlist {
			if v == account {
				return fmt.Errorf("your account [%s] does not have permissions", account)
			}
		}
		return nil
	case configs.Access_Private:
		for _, v := range bwlist {
			if v == account {
				return nil
			}
		}
	}
	return fmt.Errorf("your account [%s] does not have permissions", account)
}
