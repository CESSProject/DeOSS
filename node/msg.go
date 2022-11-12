package node

import (
	"encoding/binary"
	"encoding/json"
	"sync"

	"github.com/CESSProject/cess-oss/configs"
)

type MsgType byte

const (
	MsgInvalid MsgType = iota
	MsgHead
	MsgFile
	MsgEnd
	MsgNotify
	MsgClose
	MsgRecvHead
	MsgRecvFile
)

const (
	FileType_file   uint8 = 1
	FileType_filler uint8 = 2
)

type Status byte

const (
	Status_Ok Status = iota
	Status_Err
)

type Message struct {
	Pubkey   []byte  `json:"pubkey"`
	SignMsg  []byte  `json:"signmsg"`
	Sign     []byte  `json:"sign"`
	Bytes    []byte  `json:"bytes"`
	FileName string  `json:"filename"`
	FileHash string  `json:"filehash"`
	FileSize uint64  `json:"filesize"`
	MsgType  MsgType `json:"msgtype"`
	LastMark bool    `json:"lastmark"`
	FileType uint8   `json:"filetype"`
}

type Notify struct {
	Status byte
}

var (
	msgPool = &sync.Pool{
		New: func() interface{} {
			return &Message{}
		},
	}

	bytesPool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, configs.TCP_SendBuffer)
		},
	}
)

func (m *Message) GC() {
	if m.MsgType == MsgFile {
		bytesPool.Put(m.Bytes[:cap(m.Bytes)])
	}
	m.reset()
	msgPool.Put(m)
}

func (m *Message) reset() {
	m.MsgType = MsgInvalid
	m.FileName = ""
	m.FileHash = ""
	m.FileSize = 0
	m.LastMark = false
	m.Pubkey = nil
	m.SignMsg = nil
	m.Sign = nil
	m.Bytes = nil
}

func (m *Message) String() string {
	bytes, _ := json.Marshal(m)
	return string(bytes)
}

// Decode will convert from bytes
func Decode(b []byte) (m *Message, err error) {
	m = msgPool.Get().(*Message)
	err = json.Unmarshal(b, &m)
	return
}

func NewNotifyMsg(fileName string, status Status) *Message {
	m := msgPool.Get().(*Message)
	m.MsgType = MsgNotify
	m.Bytes = []byte{byte(status)}
	m.FileName = fileName
	m.FileHash = ""
	m.Pubkey = nil
	m.SignMsg = nil
	m.Sign = nil
	return m
}

func NewHeadMsg(fileName string, fid string, lastmark bool, pkey, signmsg, sign []byte) *Message {
	m := msgPool.Get().(*Message)
	m.MsgType = MsgHead
	m.FileName = fileName
	m.FileHash = fid
	m.LastMark = lastmark
	m.Pubkey = pkey
	m.SignMsg = signmsg
	m.Sign = sign
	return m
}

func NewRecvHeadMsg(fid string, pkey, signmsg, sign []byte) *Message {
	m := msgPool.Get().(*Message)
	m.MsgType = MsgRecvHead
	m.FileName = fid
	m.Pubkey = pkey
	m.SignMsg = signmsg
	m.Sign = sign
	return m
}

func NewRecvFileMsg(fid string) *Message {
	m := msgPool.Get().(*Message)
	m.MsgType = MsgRecvFile
	m.FileName = fid
	m.Pubkey = nil
	m.SignMsg = nil
	m.Sign = nil
	return m
}

func NewFileMsg(fileName string, buf []byte) *Message {
	m := msgPool.Get().(*Message)
	m.MsgType = MsgFile
	m.FileName = fileName
	m.Bytes = buf
	// m.Bytes = make([]byte, len(buf))
	// copy(m.Bytes, buf)
	return m
}

func NewEndMsg(fileName, fileHash string, size, originSize uint64, lastmark bool) *Message {
	m := msgPool.Get().(*Message)
	uintbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(uintbytes, originSize)
	m.SignMsg = uintbytes
	m.MsgType = MsgEnd
	m.FileName = fileName
	m.FileHash = fileHash
	m.FileSize = size
	m.LastMark = lastmark
	return m
}

func NewCloseMsg(fileName string, status Status) *Message {
	m := msgPool.Get().(*Message)
	m.MsgType = MsgClose
	m.Bytes = []byte{byte(status)}
	m.FileName = fileName
	return m
}
