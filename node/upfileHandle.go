/*
   Copyright 2022 CESS scheduler authors

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

package node

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/erasure"
	"github.com/CESSProject/cess-oss/pkg/hashtree"
	"github.com/CESSProject/cess-oss/pkg/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// It is used to authorize users
func (n *Node) upfileHandle(c *gin.Context) {
	var (
		err error
		acc string
	)
	// token
	tokenString := c.Request.Header.Get(configs.Header_Auth)
	if tokenString == "" {
		//Uld.Sugar().Infof("[%v] head missing token", c.ClientIP())
		c.JSON(403, "NoPermission")
		return
	}

	mySigningKey, err := n.Cache.Get([]byte("SigningKey"))
	if err != nil {
		c.JSON(400, "InternalError")
		return
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return mySigningKey, nil
		})

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		acc = claims.Account
	} else {
		c.JSON(403, "NoPermission")
		return
	}

	pkey, err := utils.DecodePublicKeyOfCessAccount(acc)
	if err != nil {
		c.JSON(400, "InvalidParameter.Token")
		return
	}

	//
	grantor, err := n.Chain.GetGrantor(pkey)
	if err != nil {
		c.JSON(400, err.Error())
		return
	}

	account_chain, _ := utils.EncodePublicKeyAsCessAccount(grantor[:])
	account_local, _ := n.Chain.GetCessAccount()
	if account_chain != account_local {
		if err != nil {
			c.JSON(400, "Unauthorized")
			return
		}
	}

	filename := c.Param("filename")
	if filename == "" {
		//Uld.Sugar().Infof("[%v] no file name", usertoken.Mailbox)
		c.JSON(400, "Invalid.Filename")
		return
	}

	content_length := c.Request.ContentLength
	if content_length <= 0 {
		//Uld.Sugar().Infof("[%v] contentLength <= 0", usertoken.Mailbox)
		c.JSON(400, "Empty file")
		return
	}

	// save file
	file_c, _, err := c.Request.FormFile("file")
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(400, err.Error())
		return
	}

	_, err = os.Stat(n.FileDir)
	if err != nil {
		err = os.MkdirAll(n.FileDir, os.ModeDir)
		if err != nil {
			//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
			c.JSON(500, err.Error())
			return
		}
	}

	// Calc file path
	fpath := filepath.Join(n.FileDir, url.QueryEscape(filename))

	// Create file
	f, err := os.Create(fpath)
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, err.Error())
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
			c.JSON(400, err.Error())
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
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, "UnexpectedError")
	}

	// Calc reedsolomon
	chunkPath, datachunkLen, rduchunkLen, err := erasure.ReedSolomon(fpath)
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, err.Error())
	}

	if len(chunkPath) != (datachunkLen + rduchunkLen) {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, "ReedSolomon failed")
		c.JSON(500, "UnexpectedError")
	}

	// Calc merkle hash tree
	hTree, err := hashtree.NewHashTree(chunkPath)
	if err != nil {
		//Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		c.JSON(500, "UnexpectedError")
	}

	// Merkel root hash
	hashtree := hex.EncodeToString(hTree.MerkleRoot())

	// Rename the file and chunks with root hash
	var newChunksPath = make([]string, 0)
	newpath := filepath.Join(n.FileDir, hashtree)
	os.Rename(fpath, newpath)
	if rduchunkLen == 0 {
		newChunksPath = append(newChunksPath, hashtree)
	} else {
		for i := 0; i < len(chunkPath); i++ {
			var ext = filepath.Ext(chunkPath[i])
			var newchunkpath = filepath.Join(n.FileDir, hashtree+ext)
			os.Rename(chunkPath[i], newchunkpath)
			newChunksPath = append(newChunksPath, hashtree+ext)
		}
	}

	// Declaration file
	txhash, err := chain.UploadDeclaration(configs.C.AccountSeed, fileid, filename)
	if txhash == "" {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
}
