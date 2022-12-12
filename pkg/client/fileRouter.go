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
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/CESSProject/cess-oss/configs"
)

var sendFileBufPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, configs.SIZE_1MiB)
	},
}

type MsgFile struct {
	Token    string `json:"token"`
	FileHash string `json:"filehash"`
	Data     []byte `json:"data"`
}

func FileReq(conn net.Conn, token string, files []string) error {
	var (
		err     error
		num     int
		tempBuf []byte
		msgHead IMessage
		fs      *os.File
		mesage  = MsgFile{
			Token:    token,
			FileHash: "",
			Data:     nil,
		}
		dp       = NewDataPack()
		headData = make([]byte, dp.GetHeadLen())
	)

	readBuf := sendFileBufPool.Get().([]byte)
	defer func() {
		sendFileBufPool.Put(readBuf)
	}()

	for i := 0; i < len(files); i++ {
		fs, err = os.Open(files[i])
		if err != nil {
			return err
		}
		mesage.FileHash = filepath.Base(files[i])
		for {
			num, err = fs.Read(readBuf)
			if err != nil && err != io.EOF {
				return err
			}
			if num == 0 {
				break
			}
			mesage.Data = readBuf[:num]

			tempBuf, err = json.Marshal(&mesage)
			if err != nil {
				return err
			}

			//send auth message
			tempBuf, _ = dp.Pack(NewMsgPackage(Msg_File, tempBuf))
			_, err = conn.Write(tempBuf)
			if err != nil {
				return err
			}

			//read head
			_, err = io.ReadFull(conn, headData)
			if err != nil {
				return err
			}

			msgHead, err = dp.Unpack(headData)
			if err != nil {
				return err
			}

			if msgHead.GetMsgID() == Msg_OK_FILE {
				break
			}
		}
	}

	return err
}
