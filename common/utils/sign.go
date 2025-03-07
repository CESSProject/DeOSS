/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/mr-tron/base58"
	"github.com/vedhavyas/go-subkey/v2/sr25519"
)

// VerifySR25519WithPubkey verify sr25519 signature with account public key
//   - account: polkadot account
//   - msg: message
//   - signature: sr25519 signature
//
// Return:
//   - []byte: public key of account
//   - bool: verification result
//   - error: error message
func VerifySR25519WithPubkey(account, msg, signature string) ([]byte, bool, error) {
	if len(signature) <= 0 {
		return nil, false, errors.New("VerifySR25519WithPubkey: empty signature")
	}
	pk, err := sutils.ParsingPublickey(account)
	if err != nil {
		return nil, false, errors.New("VerifySR25519WithPubkey: invalid account")
	}
	public, err := sr25519.Scheme{}.FromPublicKey(pk)
	if err != nil {
		return pk, false, err
	}

	ok := public.Verify([]byte(msg), []byte(signature))
	if ok {
		return pk, true, nil
	}

	if strings.HasPrefix(signature, "0x") {
		sign, err := hex.DecodeString(signature[2:])
		if err == nil {
			ok = public.Verify([]byte(msg), sign)
			if ok {
				return pk, true, nil
			}
		}
	}

	sign, err := hex.DecodeString(signature)
	if err == nil {
		ok = public.Verify([]byte(msg), sign)
		if ok {
			return pk, true, nil
		}
	}

	sign, err = base58.Decode(signature)
	if err == nil {
		ok = public.Verify([]byte(msg), sign)
		if ok {
			return pk, true, nil
		}
	}

	return pk, ok, err
}

// VerifyPolkadotjsHexSign verify signature signed with polkadot.js
//   - account: polkadot account
//   - msg: message
//   - sign: signature
//
// Return:
//   - []byte: public key of account
//   - bool: verification result
//   - error: error message
//
// Tip:
//   - https://polkadot.js.org/apps/#/signing
func VerifyPolkadotjsHexSign(account, msg, signature string) ([]byte, bool, error) {
	if len(msg) == 0 {
		return nil, false, errors.New("msg is empty")
	}

	pkey, err := sutils.ParsingPublickey(account)
	if err != nil {
		return nil, false, err
	}

	pub, err := sr25519.Scheme{}.FromPublicKey(pkey)
	if err != nil {
		return pkey, false, err
	}

	sign_bytes, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		return pkey, false, err
	}
	message := fmt.Sprintf("<Bytes>%s</Bytes>", msg)
	ok := pub.Verify([]byte(message), sign_bytes)
	return pkey, ok, nil
}
