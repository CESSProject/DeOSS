package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
)

type StorageProgress struct {
	FileId      string           `json:"file_id"`
	FileState   string           `json:"file_state"`
	Scheduler   string           `json:"scheduler"`
	FileSize    int64            `json:"file_size"`
	IsUpload    bool             `json:"is_upload"`
	IsCheck     bool             `json:"is_check"`
	IsShard     bool             `json:"is_shard"`
	IsScheduler bool             `json:"is_scheduler"`
	Backups     []map[int]string `json:"backups,omitempty"`
}

type MsgStorageProgress struct {
	RootHash string `json:"roothash"`
}

func ProgressReq(conn net.Conn, fid string) ([]byte, error) {
	var mesage = MsgStorageProgress{
		RootHash: fid,
	}

	b, err := json.Marshal(&mesage)
	if err != nil {
		return nil, err
	}

	dp := NewDataPack()
	//send auth message
	msg, _ := dp.Pack(NewMsgPackage(Msg_Progress, b))
	_, err = conn.Write(msg)
	if err != nil {
		return nil, err
	}

	//read head
	headData := make([]byte, dp.GetHeadLen())
	_, err = io.ReadFull(conn, headData)
	if err != nil {
		return nil, err
	}

	msgHead, err := dp.Unpack(headData)
	if err != nil {
		return nil, err
	}

	if msgHead.GetDataLen() > 0 {
		//read data
		msg := msgHead.(*Message)
		msg.Data = make([]byte, msg.GetDataLen())

		_, err := io.ReadFull(conn, msg.Data)
		if err != nil {
			return nil, err
		}
		var fileSt StorageProgress
		err = json.Unmarshal(msg.Data, &fileSt)
		if err != nil {
			return nil, err

		}
		return msg.Data, nil
	}
	return nil, fmt.Errorf("Nil head")
}
