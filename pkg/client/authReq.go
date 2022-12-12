/*
   Copyright 2022 CESS (Cumulus Encrypted Storage System) authors

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

package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/CESSProject/cess-oss/pkg/utils"
	cesskeyring "github.com/CESSProject/go-keyring"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
)

type MsgAuth struct {
	Account string `json:"account"`
	Msg     string `json:"msg"`
	Sign    []byte `json:"sign"`
}

func AuthReq(conn net.Conn, secret string) (string, error) {
	unsignedMsg := utils.GetRandomcode(16)

	kr, _ := cesskeyring.FromURI(secret, cesskeyring.NetSubstrate{})
	// sign message
	sign, err := kr.Sign(kr.SigningContext([]byte(unsignedMsg)))
	if err != nil {
		return "", err
	}

	keyring, err := signature.KeyringPairFromSecret(secret, 0)
	if err != nil {
		return "", err
	}

	account, err := utils.EncodePublicKeyAsCessAccount(keyring.PublicKey)
	if err != nil {
		return "", err
	}

	var mesage = MsgAuth{
		Account: account,
		Msg:     unsignedMsg,
		Sign:    sign[:],
	}

	b, err := json.Marshal(&mesage)
	if err != nil {
		return "", err
	}

	dp := NewDataPack()
	//send auth message
	msg, _ := dp.Pack(NewMsgPackage(Msg_Auth, b))
	_, err = conn.Write(msg)
	if err != nil {
		return "", err
	}

	//read head
	headData := make([]byte, dp.GetHeadLen())
	_, err = io.ReadFull(conn, headData)
	if err != nil {
		return "", err
	}

	msgHead, err := dp.Unpack(headData)
	if err != nil {
		return "", err
	}

	if msgHead.GetDataLen() > 0 {
		//read data
		msg := msgHead.(*Message)
		msg.Data = make([]byte, msg.GetDataLen())

		_, err := io.ReadFull(conn, msg.Data)
		if err != nil {
			return "", err
		}
		return string(msg.Data), nil
	}
	return "", fmt.Errorf("Nil head")
}
