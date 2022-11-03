package tcp

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Server interface {
	Start() error
}

type Client interface {
	SendFile(fid string, fsize int64, pkey, signmsg, sign []byte) error
	RecvFile(fid string, fsize int64, pkey, signmsg, sign []byte) error
}

type ConMgr struct {
	conn     NetConn
	dir      string
	fileName string

	sendFiles []string

	waitNotify chan bool
	stop       chan struct{}
}

func NewServer(conn NetConn, dir string) Server {
	return &ConMgr{
		conn: conn,
		dir:  dir,
		stop: make(chan struct{}),
	}
}

func (c *ConMgr) Start() error {
	c.conn.HandlerLoop()
	return c.handler()
}

func (c *ConMgr) handler() error {
	var recvFile *os.File
	var err error

	defer func() {
		if recvFile != nil {
			_ = recvFile.Close()
		}
	}()

	for !c.conn.IsClose() {
		m, ok := c.conn.GetMsg()
		if !ok {
			return fmt.Errorf("close by connect")
		}
		if m == nil {
			continue
		}

		switch m.MsgType {
		case MsgHead:
			// if m.FileName != "" {
			// 	c.fileName = m.FileName
			// } else {
			// 	c.fileName = GenFileName()
			// }

			// fmt.Println("recv head fileName is", c.fileName)
			// fs, err = os.OpenFile(filepath.Join(c.dir, c.fileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
			// if err != nil {
			// 	fmt.Println("os.Create err =", err)
			// 	c.conn.SendMsg(NewNotifyMsg(c.fileName, Status_Err))
			// 	return err
			// }
			// fmt.Println("send head is ok")

			c.conn.SendMsg(NewNotifyMsg(c.fileName, Status_Ok))
		case MsgFile:
			if recvFile == nil {
				recvFile, err = os.OpenFile(filepath.Join(c.dir, m.FileName), os.O_RDWR|os.O_TRUNC, os.ModePerm)
				if err != nil {
					fmt.Println("open file err =", err)
					c.conn.SendMsg(NewCloseMsg(c.fileName, Status_Err))
					return err
				}
			}
			_, err = recvFile.Write(m.Bytes)
			if err != nil {
				fmt.Println("file.Write err =", err)
				c.conn.SendMsg(NewCloseMsg(m.FileName, Status_Err))
				return err
			}
		case MsgEnd:
			info, err := recvFile.Stat()
			if err != nil {
				c.conn.SendMsg(NewCloseMsg(c.fileName, Status_Err))
				return err
			}
			if info.Size() != int64(m.FileSize) {
				err = fmt.Errorf("file.size %v rece size %v \n", info.Size(), m.FileSize)
				c.conn.SendMsg(NewCloseMsg(c.fileName, Status_Err))
				return err
			}

			fmt.Printf("save file %v is success \n", info.Name())
			//c.conn.SendMsg(NewNotifyMsg(c.fileName, Status_Ok))

			fmt.Printf("close file %v is success \n", c.fileName)
			_ = recvFile.Close()
			recvFile = nil
		case MsgNotify:
			c.waitNotify <- m.Bytes[0] == byte(Status_Ok)
		case MsgClose:
			fmt.Printf("revc close msg ....\n")
			if m.Bytes[0] != byte(Status_Ok) {
				return fmt.Errorf("server an error occurred")
			}
			return nil
		}
	}

	return err
}

func NewClient(conn NetConn, dir string, files []string) Client {
	return &ConMgr{
		conn:       conn,
		dir:        dir,
		sendFiles:  files,
		waitNotify: make(chan bool, 1),
		stop:       make(chan struct{}),
	}
}

func (c *ConMgr) SendFile(fid string, fsize int64, pkey, signmsg, sign []byte) error {
	fmt.Println("--1--")
	var err error
	c.conn.HandlerLoop()
	go func() {
		fmt.Println("--2--")
		_ = c.handler()
	}()
	fmt.Println("--3--")
	err = c.sendFile(fid, fsize, pkey, signmsg, sign)
	return err
}

func (c *ConMgr) RecvFile(fid string, fsize int64, pkey, signmsg, sign []byte) error {
	var err error
	c.conn.HandlerLoop()
	go func() {
		_ = c.handler()
	}()
	err = c.recvFile(fid, fsize, pkey, signmsg, sign)
	return err
}

func (c *ConMgr) sendFile(fid string, fsize int64, pkey, signmsg, sign []byte) error {
	defer func() {
		_ = c.conn.Close()
	}()

	var err error
	var lastmatrk bool

	for i := 0; i < len(c.sendFiles); i++ {
		if (i + 1) == len(c.sendFiles) {
			lastmatrk = true
		}
		fmt.Println("lastmark: ", lastmatrk)
		err = c.sendSingleFile(filepath.Join(c.dir, c.sendFiles[i]), fid, fsize, lastmatrk, pkey, signmsg, sign)
		if err != nil {
			return err
		}
		if strings.Contains(c.sendFiles[i], ".") {
			os.Remove(filepath.Join(c.dir, c.sendFiles[i]))
		}
	}

	c.conn.SendMsg(NewCloseMsg(c.fileName, Status_Ok))
	return err
}

func (c *ConMgr) recvFile(fid string, fsize int64, pkey, signmsg, sign []byte) error {
	defer func() {
		_ = c.conn.Close()
	}()

	log.Println("Ready to recvhead: ", fid)
	m := NewRecvHeadMsg(fid, pkey, signmsg, sign)
	c.conn.SendMsg(m)
	timer := time.NewTimer(time.Second * 5)
	select {
	case ok := <-c.waitNotify:
		if !ok {
			return fmt.Errorf("send err")
		}
	case <-timer.C:
		return fmt.Errorf("wait server msg timeout")
	}

	_, err := os.Create(filepath.Join(c.dir, fid))
	if err != nil {
		c.conn.SendMsg(NewCloseMsg(fid, Status_Err))
		return err
	}
	log.Println("Ready to recvfile: ", fid)
	m = NewRecvFileMsg(fid)
	c.conn.SendMsg(m)

	waitTime := fsize / 1024 / 10
	if waitTime < 5 {
		waitTime = 5
	}

	timer = time.NewTimer(time.Second * time.Duration(waitTime))
	select {
	case ok := <-c.waitNotify:
		if !ok {
			return fmt.Errorf("send err")
		}
	case <-timer.C:
		return fmt.Errorf("wait server msg timeout")
	}
	c.conn.SendMsg(NewCloseMsg(fid, Status_Ok))
	timer = time.NewTimer(time.Second * 5)
	select {
	case <-timer.C:
		return nil
	}
}

func (c *ConMgr) sendSingleFile(filePath string, fid string, fsize int64, lastmark bool, pkey, signmsg, sign []byte) error {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("open file err %v \n", err)
		return err
	}

	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()
	fileInfo, _ := file.Stat()

	log.Println("Ready to write file: ", filePath)
	m := NewHeadMsg(fileInfo.Name(), fid, lastmark, pkey, signmsg, sign)
	c.conn.SendMsg(m)

	timer := time.NewTimer(5 * time.Second)
	select {
	case ok := <-c.waitNotify:
		if !ok {
			return fmt.Errorf("send err")
		}
	case <-timer.C:
		return fmt.Errorf("wait server msg timeout")
	}

	for !c.conn.IsClose() {
		readBuf := BytesPool.Get().([]byte)

		n, err := file.Read(readBuf)
		if err != nil && err != io.EOF {
			return err
		}

		if n == 0 {
			break
		}

		c.conn.SendMsg(NewFileMsg(c.fileName, readBuf[:n]))
	}

	c.conn.SendMsg(NewEndMsg(c.fileName, fid, uint64(fileInfo.Size()), uint64(fsize), lastmark))
	waitTime := fileInfo.Size() / 1024 / 10
	if waitTime < 5 {
		waitTime = 5
	}

	timer = time.NewTimer(time.Second * time.Duration(waitTime))
	select {
	case ok := <-c.waitNotify:
		if !ok {
			return fmt.Errorf("send err")
		}
	case <-timer.C:
		return fmt.Errorf("wait server msg timeout")
	}

	log.Println("Send " + filePath + " file success...")
	return nil
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func GenFileName() string {
	u := uuid.New()
	return u.String()

}
