/*
Copyright (C) CESS. All rights reserved.
Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
)

// func (n *Node) PreviewFile(c *gin.Context) {
// 	if _, ok := <-max_concurrent_get_ch; !ok {
// 		c.JSON(http.StatusTooManyRequests, "server is busy, please try again later.")
// 		return
// 	}
// 	defer func() { max_concurrent_get_ch <- true }()

// 	fid := c.Param(HTTP_ParameterName_Fid)
// 	account := c.Request.Header.Get(HTTPHeader_Account)
// 	format := c.Request.Header.Get(HTTPHeader_Format)
// 	rgn := c.Request.Header.Get(HTTPHeader_Range)
// 	clientIp := c.Request.Header.Get("X-Forwarded-For")
// 	if clientIp == "" {
// 		clientIp = c.ClientIP()
// 	}

// 	if strings.Contains(fid, ".") {
// 		temp := strings.Split(fid, ".")
// 		fid = temp[0]
// 		if format == "" && len(temp) > 1 {
// 			format = temp[1]
// 		}
// 	} else {
// 		if len(fid) > chain.FileHashLen {
// 			tmp_fid := fid[:chain.FileHashLen]
// 			format = fid[chain.FileHashLen:]
// 			fid = tmp_fid
// 		} else if len(fid) < chain.FileHashLen {
// 			n.Logopen("err", clientIp+" invalid fid: "+fid)
// 			c.JSON(404, "invalid fid")
// 			return
// 		}
// 	}

// 	n.Logopen("info", clientIp+" open file: "+fid+" account: "+account+" format: "+format+" Range: "+rgn)

// 	var err error
// 	var contenttype any
// 	if format == "" {
// 		code := 0
// 		content_type := ""
// 		recordInfo, err := n.ParseTrackFile(fid)
// 		if err != nil {
// 			format, content_type, code, err = n.QueryFileType(fid, account)
// 			if err != nil {
// 				n.Logopen("err", clientIp+" QueryFileType: "+err.Error())
// 				c.JSON(code, "Please wait for the file to be on chain before operating")
// 				return
// 			}
// 			contenttype = content_type
// 		} else {
// 			ok := false
// 			format = filepath.Ext(recordInfo.FileName)
// 			contenttype, ok = contentType.Load(strings.ToLower(format))
// 			if !ok {
// 				contenttype = "application/octet-stream"
// 			}
// 		}

// 	} else {
// 		if !strings.HasPrefix(format, ".") {
// 			format = "." + format
// 		}
// 		ok := false
// 		contenttype, ok = contentType.Load(strings.ToLower(format))
// 		if !ok {
// 			n.Logopen("err", clientIp+" contentType.Load failed: unknown file format")
// 			c.JSON(http.StatusBadRequest, "unknown file format")
// 			return
// 		}
// 	}

// 	n.Logopen("info", clientIp+" file format: "+format+" content type: "+contenttype.(string))

// 	size, fpath, err := n.CheckLocalFile(fid)
// 	if err == nil && size > 0 {
// 		f, err := os.Open(fpath)
// 		if err != nil {
// 			n.Logopen("info", clientIp+" open the file from local, open file failed: "+err.Error())
// 			c.JSON(http.StatusInternalServerError, err.Error())
// 			return
// 		}
// 		n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from local", clientIp, fid))
// 		if rgn != "" {
// 			err = rangeRequest(c, rgn, contenttype.(string), fpath)
// 			n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from local by range, err: %v", clientIp, fid, err))
// 			return
// 		}
// 		n.ReturnFile(c, f, fid, contenttype.(string), format, size)
// 		return
// 	}

// 	fpath = filepath.Join(n.fileDir, fid)
// 	peerList, _ := n.QueryAllOssPeerId(-1)
// 	for _, v := range peerList {
// 		n.Logopen("info", fmt.Sprintf("[%s] will req to gateway: %s", clientIp, v))
// 		addr, ok := n.GetPeer(v)
// 		if !ok {
// 			continue
// 		}
// 		if n.ID().String() == v {
// 			continue
// 		}
// 		n.Peerstore().AddAddrs(addr.ID, addr.Addrs, time.Minute)
// 		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
// 		defer cancel()
// 		_, err = n.ReadDataAction(ctx, addr.ID, fid, fpath)
// 		if err != nil {
// 			n.Logopen("info", clientIp+" open the file from gateway, ReadDataAction failed: "+err.Error())
// 			n.Peerstore().ClearAddrs(addr.ID)
// 			continue
// 		}
// 		n.Peerstore().ClearAddrs(addr.ID)
// 		f, err := os.Open(fpath)
// 		if err != nil {
// 			n.Logopen("info", clientIp+" open the file from gateway, os.Open failed: "+err.Error())
// 			c.JSON(http.StatusInternalServerError, err.Error())
// 			return
// 		}
// 		n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from gateway", clientIp, fid))
// 		if rgn != "" {
// 			err = rangeRequest(c, rgn, contenttype.(string), fpath)
// 			n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from local by range, err: %v", clientIp, fid, err))
// 			return
// 		}
// 		n.ReturnFile(c, f, fid, contenttype.(string), format, size)
// 		return
// 	}

// 	// if !completion {
// 	// 	n.Logopen("err", fmt.Sprintf("[%s] download file [%s] : %v", clientIp, fid, "The file is being stored, please download it from the gateway where you uploaded it."))
// 	// 	c.JSON(http.StatusNotFound, "The file is being stored, please download it from the gateway where you uploaded it.")
// 	// 	return
// 	// }

// 	// download from miner
// 	fpath, err = n.retrieve_file(fid, n.fileDir, "")
// 	if err != nil {
// 		n.Logopen("err", fmt.Sprintf("[%s] Download file [%s] : %v", clientIp, fid, err))
// 		if strings.Contains(err.Error(), "being retrieved") {
// 			c.JSON(http.StatusForbidden, err.Error())
// 			return
// 		}
// 		c.JSON(http.StatusInternalServerError, "File download failed, it is recommended to use another gateway.")
// 		return
// 	}
// 	n.Logopen("info", fmt.Sprintf("[%s] Download file [%s] suc", clientIp, fid))
// 	f, err := os.Open(fpath)
// 	if err != nil {
// 		n.Logopen("info", clientIp+" open the file from miner, open file failed: "+err.Error())
// 		c.JSON(http.StatusInternalServerError, err.Error())
// 		return
// 	}
// 	n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from miner", clientIp, fid))
// 	if rgn != "" {
// 		err = rangeRequest(c, rgn, contenttype.(string), fpath)
// 		n.Logopen("info", fmt.Sprintf("[%s] return the file [%s] from local by range, err: %v", clientIp, fid, err))
// 		return
// 	}
// 	n.ReturnFile(c, f, fid, contenttype.(string), format, size)
// }

func (n *Node) QueryFileType(fid string, account string) (string, string, int, error) {
	format := ""
	fmeta, err := n.QueryFile(fid, -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			return "", "", http.StatusInternalServerError, err
		}
		order, err := n.QueryDealMap(fid, -1)
		if err != nil {
			if err.Error() != chain.ERR_Empty {
				return "", "", http.StatusInternalServerError, err
			}
			return "", "", http.StatusNotFound, err
		}
		format = filepath.Ext(string(order.User.FileName))
		contenttype, ok := contentType.Load(strings.ToLower(format))
		if !ok {
			contenttype = "application/octet-stream"
		}
		return format, contenttype.(string), http.StatusOK, nil
	}
	if account != "" {
		pkey, err := sutils.ParsingPublickey(account)
		if err != nil {
			return "", "", http.StatusBadRequest, err
		}
		for i := 0; i < len(fmeta.Owner); i++ {
			if sutils.CompareSlice(fmeta.Owner[i].User[:], pkey) {
				format = filepath.Ext(string(fmeta.Owner[i].FileName))
				contenttype, ok := contentType.Load(strings.ToLower(format))
				if !ok {
					contenttype = "application/octet-stream"
				}
				return format, contenttype.(string), http.StatusOK, nil
			}
		}
	}
	for i := 0; i < len(fmeta.Owner); i++ {
		format = filepath.Ext(string(fmeta.Owner[i].FileName))
		contenttype, ok := contentType.Load(strings.ToLower(format))
		if !ok {
			continue
		}
		return format, contenttype.(string), http.StatusOK, nil
	}
	return "", "", http.StatusBadRequest, errors.New("unknown file format")
}

func (n *Node) ReturnFile(c *gin.Context, reader io.Reader, fid, contenttype, format string, size int64) {
	switch strings.ToLower(format) {
	case ".mp4", ".mov", ".avi", ".asf", ".asx", ".rm", ".rmvb", ".3gp", ".m4v", ".wmv", ".mkv", ".flv", ".f4v", ".vob", ".mpeg",
		".wav", ".flac", ".ape", ".alac", ".wv", ".mp3", ".aac", ".wma", ".mp2", ".ra", ".midi", ".cda", ".m4a":
		VideoAndAudioHeader(c, fid)
	default:
		OtherHeader(c, fid)
	}
	c.DataFromReader(http.StatusOK, size, contenttype, reader, nil)
}

func VideoAndAudioHeader(c *gin.Context, fname string) {
	c.Header("Accept-ranges", "bytes")
	c.Writer.Header().Add("Access-control-allow-headers", "Content-Type")
	c.Writer.Header().Add("Access-control-allow-headers", "Range")
	c.Writer.Header().Add("Access-control-allow-headers", "User-Agent")
	c.Writer.Header().Add("Access-control-allow-headers", "X-Request-With")
	c.Header("Accept-control-allow-methods", "GET")
	c.Header("Accept-control-allow-origin", "*")
	c.Writer.Header().Add("Accept-control-expose-headers", "Content-Range")
	c.Writer.Header().Add("Accept-control-expose-headers", "X-Chunked-Output")
	c.Writer.Header().Add("Accept-control-expose-headers", "X-Stream-Output")
	c.Header("Cache-control", "public, max-age=29030400, immutable")
	c.Header("Content-disposition", fmt.Sprintf("inline; filename=%v", fname))
}

func OtherHeader(c *gin.Context, fname string) {
	c.Header("Accept-ranges", "bytes")
	c.Header("Accept-control-allow-origin", "*")
	c.Header("Cache-control", "public, max-age=2592000, no-transform, immutable")
	c.Header("Content-disposition", fmt.Sprintf("inline; filename=%v", fname))
}

func rangeRequest(c *gin.Context, rng string, content_type string, file string) error {
	f, err := os.Open(file)
	if err != nil {
		c.String(http.StatusNotFound, "File not found")
		return fmt.Errorf("stat file err: %v", err)
	}
	defer f.Close()

	fstat, err := f.Stat()
	if err != nil {
		c.String(http.StatusInternalServerError, "Error getting file info")
		return fmt.Errorf("stat file err: %v", err)
	}

	ranges := strings.Split(rng, "=")
	if len(ranges) != 2 || ranges[0] != "bytes" {
		c.String(http.StatusRequestedRangeNotSatisfiable, "Invalid range header")
		return fmt.Errorf("invalid range request: %s", rng)
	}

	rangeParts := strings.Split(ranges[1], "-")
	if len(rangeParts) != 2 {
		c.String(http.StatusRequestedRangeNotSatisfiable, "Invalid range header")
		return fmt.Errorf("invalid range request: %s", rng)
	}

	start, err := strconv.ParseInt(rangeParts[0], 10, 64)
	if err != nil || start < 0 {
		c.String(http.StatusRequestedRangeNotSatisfiable, "Invalid range start")
		return fmt.Errorf("invalid range request: %s", rng)
	}

	var end int64
	if rangeParts[1] != "" {
		end, err = strconv.ParseInt(rangeParts[1], 10, 64)
		if err != nil || end < start || end >= fstat.Size() {
			c.String(http.StatusRequestedRangeNotSatisfiable, "Invalid range end")
			return fmt.Errorf("invalid range request: %s", rng)
		}
	} else {
		end = fstat.Size() - 1
	}

	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fstat.Size()))
	c.Header("Content-Length", strconv.FormatInt(end-start+1, 10))
	c.Header("Content-type", content_type)
	c.Status(http.StatusPartialContent)

	f.Seek(start, io.SeekStart)
	io.CopyN(c.Writer, f, end-start+1)
	return nil
}
