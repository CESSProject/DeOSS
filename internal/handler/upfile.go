package handler

import (
	"cess-gateway/configs"
	"cess-gateway/internal/chain"
	"cess-gateway/internal/db"
	"cess-gateway/internal/erasure"
	"cess-gateway/internal/hashtree"
	. "cess-gateway/internal/logger"
	"cess-gateway/internal/tcp"
	"cess-gateway/internal/token"
	"cess-gateway/tools"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	cesskeyring "github.com/CESSProject/go-keyring"
	"github.com/gin-gonic/gin"
)

type ConnectedCtl struct {
	l    *sync.Mutex
	conn map[string]int64
}

var connctl *ConnectedCtl

func init() {
	connctl = &ConnectedCtl{
		l:    new(sync.Mutex),
		conn: make(map[string]int64, 2),
	}
}

func (this *ConnectedCtl) Is(key string) bool {
	this.l.Lock()
	defer this.l.Unlock()
	v, ok := this.conn[key]
	if ok {
		if time.Now().Unix() <= v {
			delete(this.conn, key)
			return false
		}
	}
	return ok
}

func (this *ConnectedCtl) Add(key string, value int64) {
	this.l.Lock()
	this.conn[key] = value
	this.l.Unlock()
}

func (this *ConnectedCtl) Del(key string) {
	this.l.Lock()
	defer this.l.Unlock()
	delete(this.conn, key)
}

func UpfileHandler(c *gin.Context) {
	var resp = RespMsg{
		Code: http.StatusUnauthorized,
		Msg:  Status_401_token,
	}
	// token
	htoken := c.Request.Header.Get("Authorization")
	if htoken == "" {
		Uld.Sugar().Infof("[%v] head missing token", c.ClientIP())
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	bytes, err := token.DecryptToken(htoken)
	if err != nil {
		Uld.Sugar().Infof("[%v] [%v] DecryptToken error", c.ClientIP(), htoken)
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var usertoken token.TokenMsgType
	err = json.Unmarshal(bytes, &usertoken)
	if err != nil {
		Uld.Sugar().Infof("[%v] [%v] token format error", c.ClientIP(), htoken)
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	if time.Now().Unix() >= usertoken.ExpirationTime {
		Uld.Sugar().Infof("[%v] token expired", usertoken.Mailbox)
		resp.Msg = Status_401_expired
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	db, err := db.GetDB()
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	resp.Code = http.StatusBadRequest
	resp.Msg = Status_400_default
	filename := c.Param("filename")
	if filename == "" {
		Uld.Sugar().Infof("[%v] no file name", usertoken.Mailbox)
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	key, err := tools.CalcMD5(usertoken.Mailbox + url.QueryEscape(filename))
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
	ok, err := db.Has(key)
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
	if ok {
		resp.Code = http.StatusForbidden
		resp.Msg = Status_403_dufilename
		c.JSON(http.StatusForbidden, resp)
		return
	}

	content_length := c.Request.ContentLength
	if content_length <= 0 {
		Uld.Sugar().Infof("[%v] contentLength <= 0", usertoken.Mailbox)
		c.JSON(http.StatusBadRequest, resp)
		return
	}
	file_p, err := c.FormFile("file")
	if err != nil {
		Uld.Sugar().Infof("[%v] FormFile err", usertoken.Mailbox)
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	sp, err := chain.GetSpacePackageInfo(configs.C.AccountSeed)
	if err != nil {
		if err.Error() == ERR_404 {
			resp.Code = http.StatusInternalServerError
			resp.Msg = Status_500_Notfound
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_chain
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	remainSpace := sp.Remaining_space.Uint64()

	if remainSpace < uint64(file_p.Size) {
		resp.Code = http.StatusForbidden
		resp.Msg = Status_403_NotEnoughSpace
		c.JSON(http.StatusForbidden, resp)
		return
	}

	file_c, _, err := c.Request.FormFile("file")
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	// server data
	resp.Code = http.StatusInternalServerError
	resp.Msg = Status_500_unexpected

	_, err = os.Stat(configs.FileCacheDir)
	if err != nil {
		err = os.MkdirAll(configs.FileCacheDir, os.ModeDir)
		if err != nil {
			Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
	}

	// Calc file path
	fpath := filepath.Join(configs.FileCacheDir, url.QueryEscape(filename))
	_, err = os.Stat(fpath)
	if err == nil {
		Uld.Sugar().Infof("[%v] %v:%v", usertoken.Mailbox, Status_403_dufilename, fpath)
		resp.Code = http.StatusForbidden
		resp.Msg = Status_403_dufilename
		c.JSON(http.StatusForbidden, resp)
		return
	}

	// Create file
	f, err := os.Create(fpath)
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	// Save file
	buf := make([]byte, 4*1024*1024)
	for {
		n, err := file_c.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			resp.Code = http.StatusGatewayTimeout
			resp.Msg = "upload failed due to network issues"
			c.JSON(http.StatusGatewayTimeout, resp)
			return
		}
		if n == 0 {
			continue
		}
		f.Write(buf[:n])
	}
	f.Close()

	// Calc file state
	fstat, err := os.Stat(fpath)
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
	}

	// Calc reedsolomon
	chunkPath, datachunkLen, rduchunkLen, err := erasure.ReedSolomon(fpath, fstat.Size())
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
	}

	if len(chunkPath) != (datachunkLen + rduchunkLen) {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, "ReedSolomon failed")
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
	}
	fmt.Println("--1: ", chunkPath, datachunkLen, rduchunkLen)
	// Calc merkle hash tree
	hTree, err := hashtree.NewHashTree(chunkPath)
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
	}

	// Merkel root hash
	fileid := hex.EncodeToString(hTree.MerkleRoot())
	fmt.Println("--2: ", fileid)
	// Rename the file and chunks with root hash
	var newChunksPath = make([]string, 0)
	newpath := filepath.Join(configs.FileCacheDir, fileid)
	os.Rename(fpath, newpath)
	if rduchunkLen == 0 {
		newChunksPath = append(newChunksPath, fileid)
	} else {
		for i := 0; i < len(chunkPath); i++ {
			var ext = filepath.Ext(chunkPath[i])
			var newchunkpath = filepath.Join(configs.FileCacheDir, fileid+ext)
			os.Rename(chunkPath[i], newchunkpath)
			newChunksPath = append(newChunksPath, fileid+ext)
		}
	}
	fmt.Println("--3: ", newChunksPath)
	// Declaration file
	txhash, err := chain.UploadDeclaration(configs.C.AccountSeed, fileid, filename)
	if txhash == "" {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	key_fid := usertoken.Mailbox + fileid
	err = db.Put([]byte(key), []byte(key_fid))
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
	err = db.Put([]byte(key_fid), []byte(key))
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	go task_StoreFile(newChunksPath, usertoken.Mailbox, fileid, filename, fstat.Size())
	resp.Code = http.StatusOK
	resp.Msg = Status_200_default
	resp.Data = fmt.Sprintf("%v", fileid)
	c.JSON(http.StatusOK, resp)
	return
}

func task_StoreFile(fpath []string, mailbox, fid, fname string, fsize int64) {
	defer func() {
		if err := recover(); err != nil {
			Err.Sugar().Errorf("%v", err)
		}
	}()
	var channel_1 = make(chan uint8, 1)
	Uld.Sugar().Infof("[%v] Start the file backup management process", fid)
	go uploadToStorage(channel_1, fpath, mailbox, fid, fname, fsize)
	for {
		select {
		case result := <-channel_1:
			if result == 1 {
				go uploadToStorage(channel_1, fpath, mailbox, fid, fname, fsize)
				time.Sleep(time.Second * 6)
			}
			if result == 2 {
				Uld.Sugar().Infof("[%v] File save successfully", fid)
				return
			}
			if result == 3 {
				Uld.Sugar().Infof("[%v] File save failed", fid)
				return
			}
		}
	}
}

// Upload files to cess storage system
func uploadToStorage(ch chan uint8, fpath []string, mailbox, fid, fname string, fsize int64) {
	defer func() {
		err := recover()
		if err != nil {
			ch <- 1
			Uld.Sugar().Infof("[panic]: [%v] [%v] %v", mailbox, fpath, err)
		}
	}()

	var existFile = make([]string, 0)
	for i := 0; i < len(fpath); i++ {
		_, err := os.Stat(filepath.Join(configs.FileCacheDir, fpath[i]))
		if err != nil {
			continue
		}
		existFile = append(existFile, fpath[i])
	}
	fmt.Println("--4: ", existFile)
	msg := tools.GetRandomcode(16)

	kr, _ := cesskeyring.FromURI(configs.C.AccountSeed, cesskeyring.NetSubstrate{})
	// sign message
	sign, err := kr.Sign(kr.SigningContext([]byte(msg)))
	if err != nil {
		ch <- 1
		Uld.Sugar().Infof("[%v] %v", mailbox, err)
		return
	}

	// Get all scheduler
	schds, err := chain.GetSchedulerInfo()
	if err != nil {
		ch <- 1
		Uld.Sugar().Infof("[%v] %v", mailbox, err)
		return
	}

	tools.RandSlice(schds)

	for i := 0; i < len(schds); i++ {
		wsURL := fmt.Sprintf("%d.%d.%d.%d:%d",
			schds[i].Ip.Value[0],
			schds[i].Ip.Value[1],
			schds[i].Ip.Value[2],
			schds[i].Ip.Value[3],
			schds[i].Ip.Port,
		)
		fmt.Println("Will send to ", wsURL)
		tcpAddr, err := net.ResolveTCPAddr("tcp", wsURL)
		if err != nil {
			Uld.Sugar().Infof("[%v] %v", mailbox, err)
			continue
		}
		dialer := net.Dialer{Timeout: time.Duration(time.Second * 5)}
		netConn, err := dialer.Dial("tcp", tcpAddr.String())
		if err != nil {
			Uld.Sugar().Infof("[%v] %v", mailbox, err)
			continue
		}

		conTcp, ok := netConn.(*net.TCPConn)
		if !ok {
			Uld.Sugar().Infof("[%v] ", err)
			continue
		}

		tcpCon := tcp.NewTcp(conTcp)
		srv := tcp.NewClient(tcpCon, configs.FileCacheDir, existFile)
		fmt.Println(configs.FileCacheDir)
		fmt.Println(existFile)
		err = srv.SendFile(fid, fsize, configs.PublicKey, []byte(msg), sign[:])
		if err != nil {
			Uld.Sugar().Infof("[%v] %v", mailbox, err)
			continue
		}
		ch <- 2
		return
	}
	ch <- 1
}
