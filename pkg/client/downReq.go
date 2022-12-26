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
	"os"
	"path/filepath"
)

type MsgDown struct {
	Token     string `json:"token"`
	SliceHash string `json:"slicehash"`
	FileSize  int64  `json:"filesize"`
	Index     uint32 `json:"index"`
}

func DownReq(conn net.Conn, token, fpath string, fsize int64) error {
	var (
		err     error
		tempBuf []byte
		num     int
		msgHead IMessage
		fs      *os.File
		message = MsgDown{
			Token:     token,
			SliceHash: "",
			FileSize:  fsize,
			Index:     0,
		}
		dp       = NewDataPack()
		headData = make([]byte, dp.GetHeadLen())
	)

	readBuf := sendFileBufPool.Get().([]byte)
	defer func() {
		sendFileBufPool.Put(readBuf)
		if fs != nil {
			fs.Close()
		}
	}()

	fs, err = os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	fstat, _ := fs.Stat()
	message.Index = uint32(fstat.Size())

	message.SliceHash = filepath.Base(fpath)

	for {
		tempBuf, err = json.Marshal(&message)
		if err != nil {
			return err
		}

		//send message
		tempBuf, _ = dp.Pack(NewMsgPackage(Msg_Down, tempBuf))
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

		if msgHead.GetMsgID() == Msg_OK {
			if msgHead.GetDataLen() > 0 {
				num, err = io.ReadFull(conn, readBuf)
				if err != nil {
					return err
				}
				fs.Write(readBuf[:num])
				fs.Sync()
			}
		} else {
			return fmt.Errorf("read file error")
		}

		fstat, _ = fs.Stat()
		if fstat.Size() >= fsize {
			return nil
		}
		message.Index = uint32(fstat.Size())
	}
}
