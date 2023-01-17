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

package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/CESSProject/cess-oss/pkg/client"
	"github.com/CESSProject/cess-oss/pkg/utils"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// VerifyToken is used to parse and verify token
func (n *Node) VerifyToken(c *gin.Context) (int, string, error) {
	var (
		ok       bool
		err      error
		tokenstr string
		claims   *CustomClaims
		token    *jwt.Token
		account  string
		signKey  []byte
	)
	// get token from head
	tokenstr = c.Request.Header.Get(Header_Auth)
	if tokenstr == "" {
		return http.StatusBadRequest, account, errors.New(ERR_MissToken)
	}

	// parse token
	signKey, err = utils.CalcMD5(n.Cfile.GetCtrlPrk())
	if err != nil {
		return http.StatusInternalServerError, account, errors.New(ERR_EmptySeed)
	}

	token, err = jwt.ParseWithClaims(
		tokenstr,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return signKey, nil
		})

	if claims, ok = token.Claims.(*CustomClaims); ok && token.Valid {
		account = claims.Account
	} else {
		return http.StatusForbidden, account, errors.New(ERR_NoPermission)
	}
	return http.StatusOK, account, nil
}

// PutBucket is used to create buckets
func (n *Node) PutBucket(bucketname string, pubkey []byte) (int, error) {
	var (
		err    error
		msg    string
		txHash string
	)
	if VerifyBucketName(bucketname) {
		txHash, err = n.Chn.CreateBucket(pubkey, bucketname)
		if err != nil {
			if txHash != "" {
				msg = fmt.Sprintf("Please go to the block browser to check the result, the transaction hash is as follows:\n    %v\n", txHash)
				msg += fmt.Sprintf("If there is a %v event, it means the transaction is successful.", chain.EVENT_FileBank_CreateBucket)
			} else {
				msg = ERR_ReportProblem + err.Error()
			}
			return http.StatusInternalServerError, errors.New(msg)
		}
		return http.StatusOK, nil
	}
	return http.StatusBadRequest, errors.New(ERR_InvalidBucketName)
}

// VerifyGrantor is used to verify whether the right to use the space is authorized
func (n *Node) VerifyGrantor(pubkey []byte) (int, error) {
	var (
		err     error
		grantor types.AccountID
	)

	grantor, err = n.Chn.GetGrantor(pubkey)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			return http.StatusBadRequest, errors.New(ERR_UnauthorizedSpace)
		}
		return http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}
	account_chain, _ := utils.EncodePublicKeyAsCessAccount(grantor[:])
	account_local, _ := n.Chn.GetCessAccount()
	if account_chain != account_local {
		return http.StatusBadRequest, errors.New(ERR_UnauthorizedSpace)
	}
	return http.StatusOK, nil
}

// IsStored is used to determine whether the data is Stored
func (n *Node) IsStored(fileid string, userbrief chain.UserBrief) (int, error) {
	var (
		err    error
		msg    string
		txhash string
		fileSt client.StorageProgress
	)
	if fileid != "" {
		_, err = n.Chn.GetFileMetaInfo(fileid)
		if err == nil {
			txhash, err = n.Chn.FileSecreach(fileid, userbrief)
			if err != nil {
				if txhash != "" {
					msg = fmt.Sprintf("Please go to the block browser to check the result, the transaction hash is as follows:\n    %v\n", txhash)
					msg += fmt.Sprintf("If there is a %v event, it means the transaction is successful.", chain.EVENT_FileBank_FlyUpload)
				} else {
					msg = ERR_ReportProblem + err.Error()
				}
				return http.StatusInternalServerError, errors.New(msg)
			}
			return http.StatusOK, errors.New("Data has been successfully stored")
		}

		val, err := n.Cach.Get([]byte(Cach_Hash256 + fileid))
		if err == nil {
			err = json.Unmarshal(val, &fileSt)
			if err != nil {
				msg = fmt.Sprintf("%v", fileSt)
			} else {
				msg = "Data is being stored"
			}
			return http.StatusOK, errors.New(msg)
		}
	}
	return http.StatusOK, nil
}

// IsUploaded is used to determine whether the data is Stored
func (n *Node) IsUploaded(roothash string) (int, error) {
	var (
		err error
	)
	//Judge whether the file has been uploaded
	_, err = n.Chn.GetFileDealMap(roothash)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			return http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
		}
		return http.StatusOK, nil
	}
	return http.StatusOK, errors.New("Data is being stored")
}

// SaveFormFile is used to save form files
func (n *Node) SaveFormFile(c *gin.Context, account, name string) (int64, string, string, int, error) {
	var (
		err      error
		savedir  string
		fpath    string
		hashpath string
		formfile *multipart.FileHeader
	)
	savedir = filepath.Join(n.FileDir, account)
	// Create file storage directory
	_, err = os.Stat(savedir)
	if err != nil {
		err = os.MkdirAll(savedir, configs.DirPermission)
		if err != nil {
			return 0, "", "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
		}
	}

	// Calculate the full path of the file
	fpath = filepath.Join(savedir, url.QueryEscape(name))
	_, err = os.Stat(fpath)
	if err == nil {
		return 0, "", "", http.StatusBadRequest, errors.New(ERR_DuplicateFileName)
	}

	// Get form file
	formfile, err = c.FormFile(FormFileKey1)
	if err != nil {
		formfile, err = c.FormFile(FormFileKey2)
		if err != nil {
			formfile, err = c.FormFile(FormFileKey3)
			if err != nil {
				return 0, "", "", http.StatusBadRequest, errors.New(ERR_ReportProblem + err.Error())
			}
		}
	}

	// save form file
	err = c.SaveUploadedFile(formfile, fpath)
	if err != nil {
		return 0, "", "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	defer os.Remove(fpath)

	// Get file info
	finfo, err := os.Stat(fpath)
	if err != nil {
		return 0, "", "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	// Calculate file hash
	hash256, err := utils.CalcPathSHA256(fpath)
	if err != nil {
		return 0, "", "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	// Rename
	hashpath = filepath.Join(savedir, hash256)
	err = os.Rename(fpath, hashpath)
	if err != nil {
		return 0, "", "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	return finfo.Size(), hash256, hashpath, http.StatusOK, nil
}
