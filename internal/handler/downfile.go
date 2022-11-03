package handler

import (
	"cess-gateway/configs"
	"cess-gateway/internal/chain"
	"cess-gateway/internal/erasure"
	. "cess-gateway/internal/logger"
	"cess-gateway/internal/tcp"
	"cess-gateway/tools"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	cesskeyring "github.com/CESSProject/go-keyring"
	"github.com/gin-gonic/gin"
)

func DownfileHandler(c *gin.Context) {
	var resp = RespMsg{
		Code: http.StatusUnauthorized,
		Msg:  Status_401_token,
	}

	fid := c.Param("fid")
	if fid == "" {
		Err.Sugar().Errorf("[%v] fid is empty", c.ClientIP())
		resp.Code = http.StatusBadRequest
		resp.Msg = Status_400_default
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	// local cache
	fpath := filepath.Join(configs.FileCacheDir, fid)
	_, err := os.Stat(fpath)
	if err == nil {
		//c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filehash))
		c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%v", fid))
		c.Writer.Header().Add("Content-Type", "application/octet-stream")
		c.File(fpath)
		return
	}

	// file meta info
	fmeta, err := chain.GetFileMetaInfoOnChain(fid)
	if err != nil {
		Err.Sugar().Errorf("[%v] %v", c.ClientIP(), err)
		if err.Error() == chain.ERR_Empty {
			resp.Code = http.StatusNotFound
			resp.Msg = Status_400_NotUploaded
			c.JSON(http.StatusNotFound, resp)
			return
		}
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	// if string(fmeta.FileState) != "active" {
	// 	Err.Sugar().Errorf("[%v] file state is not active", c.ClientIP())
	// 	resp.Code = http.StatusForbidden
	// 	resp.Msg = Status_403_hotbackup
	// 	c.JSON(http.StatusForbidden, resp)
	// 	return
	// }

	r := len(fmeta.ChunkInfo) / 3
	d := len(fmeta.ChunkInfo) - r
	down_count := 0
	for i := 0; i < len(fmeta.ChunkInfo); i++ {
		// Download the file from the scheduler service
		fname := filepath.Join(configs.FileCacheDir, string(fmeta.ChunkInfo[i].ChunkId[:]))
		if len(fmeta.ChunkInfo) == 1 {
			fname = fname[:(len(fname) - 4)]
		}
		mip := fmt.Sprintf("%d.%d.%d.%d:%d",
			fmeta.ChunkInfo[i].MinerIp.Value[0],
			fmeta.ChunkInfo[i].MinerIp.Value[1],
			fmeta.ChunkInfo[i].MinerIp.Value[2],
			fmeta.ChunkInfo[i].MinerIp.Value[3],
			fmeta.ChunkInfo[i].MinerIp.Port,
		)
		err = downloadFromStorage(fname, int64(fmeta.ChunkInfo[i].ChunkSize), mip)
		if err != nil {
			Err.Sugar().Errorf("[%v] Downloading %drd shard err: %v", c.ClientIP(), i, err)
		} else {
			down_count++
		}
		if down_count >= d {
			break
		}
	}

	err = erasure.ReedSolomon_Restore(configs.FileCacheDir, fid, d, r, uint64(fmeta.FileSize))
	if err != nil {
		Err.Sugar().Errorf("[%v] ReedSolomon_Restore: %v", c.ClientIP(), err)
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	if r > 0 {
		fstat, err := os.Stat(fpath)
		if err != nil {
			Err.Sugar().Errorf("[%v] %v", c.ClientIP(), err)
			resp.Code = http.StatusInternalServerError
			resp.Msg = Status_500_unexpected
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
		if uint64(fstat.Size()) > uint64(fmeta.FileSize) {
			tempfile := fpath + ".temp"
			copyFile(fpath, tempfile, int64(fmeta.FileSize))
			os.Remove(fpath)
			os.Rename(tempfile, fpath)
		}
	}

	//c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filehash))
	c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%v", fid))
	c.Writer.Header().Add("Content-Type", "application/octet-stream")
	c.File(fpath)
	return
}

// Download files from cess storage service
func downloadFromStorage(fpath string, fsize int64, mip string) error {
	fsta, err := os.Stat(fpath)
	if err == nil {
		if fsta.Size() == fsize {
			return nil
		} else {
			os.Remove(fpath)
		}
	}

	msg := tools.GetRandomcode(16)

	kr, _ := cesskeyring.FromURI(configs.C.AccountSeed, cesskeyring.NetSubstrate{})
	// sign message
	sign, err := kr.Sign(kr.SigningContext([]byte(msg)))
	if err != nil {
		return err
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", mip)
	if err != nil {
		return err
	}

	conTcp, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return err
	}
	srv := tcp.NewClient(tcp.NewTcp(conTcp), configs.FileCacheDir, nil)
	return srv.RecvFile(filepath.Base(fpath), fsize, configs.PublicKey, []byte(msg), sign[:])
}

func copyFile(src, dst string, length int64) error {
	srcfile, err := os.OpenFile(src, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer srcfile.Close()
	dstfile, err := os.OpenFile(src, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer dstfile.Close()

	var buf = make([]byte, 64*1024)
	var count int64
	for {
		n, err := srcfile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		count += int64(n)
		if count < length {
			dstfile.Write(buf[:n])
		} else {
			tail := count - length
			if n >= int(tail) {
				dstfile.Write(buf[:(n - int(tail))])
			}
		}
	}

	return nil
}
