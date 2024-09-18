/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

// func verifySignature(n *Node, account, ethAccount, message, signature string) ([]byte, int, error) {
// 	var (
// 		pkey []byte
// 		err  error
// 	)

// 	timestamp, err := strconv.ParseInt(message, 10, 64)
// 	if err != nil {
// 		t, err := time.Parse(time.DateTime, message)
// 		if err == nil {
// 			if time.Now().After(t) {
// 				return nil, http.StatusForbidden, errors.New("Signature has expired")
// 			}
// 		}
// 	} else {
// 		if isUnixTimestamp(timestamp) {
// 			if time.Now().Unix() >= timestamp {
// 				return nil, http.StatusForbidden, errors.New("Signature has expired")
// 			}
// 		} else if isUnixMillTimestamp(timestamp) {
// 			if time.Now().UnixMilli() >= timestamp {
// 				return nil, http.StatusForbidden, errors.New("Signature has expired")
// 			}
// 		}
// 	}

// 	if err = n.AccessControl(account); err != nil {
// 		return nil, http.StatusBadRequest, err
// 	}

// 	if ethAccount != "" {
// 		ethAccInSian, err := VerifyEthSign(message, signature)
// 		if err != nil {
// 			return nil, http.StatusBadRequest, err
// 		}
// 		if ethAccInSian != ethAccount {
// 			return nil, http.StatusBadRequest, errors.New("Signature verification failed")
// 		}
// 		pkey, err = sutils.ParsingPublickey(account)
// 		if err != nil {
// 			return nil, http.StatusBadRequest, err
// 		}
// 		if len(pkey) == 0 {
// 			return nil, http.StatusBadRequest, errors.New("Invalid account")
// 		}
// 	} else {
// 		pkey, err = n.VerifyAccountSignature(account, message, signature)
// 		if err != nil {
// 			return nil, http.StatusBadRequest, err
// 		}
// 		if len(pkey) == 0 {
// 			return nil, http.StatusBadRequest, errors.New("Invalid signature")
// 		}
// 	}

// 	return pkey, http.StatusOK, nil
// }

// func isUnixTimestamp(timestamp int64) bool {
// 	return timestamp >= 1e9 && timestamp < 1e12
// }
// func isUnixMillTimestamp(timestamp int64) bool {
// 	return timestamp >= 1e12 && timestamp < 1e15
// }
