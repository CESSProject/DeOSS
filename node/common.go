package node

import (
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/CESSProject/sdk-go/core/pattern"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// VerifyToken is used to parse and verify token
func (n *Node) VerifyToken(c *gin.Context, respmsg *RespMsg) (string, []byte, error) {
	var (
		ok       bool
		err      error
		tokenstr string
		claims   *CustomClaims
		token    *jwt.Token
		account  string
	)
	if respmsg.Err != nil {
		return account, nil, err
	}

	// get token from head
	tokenstr = c.Request.Header.Get(Header_Auth)
	if tokenstr == "" {
		respmsg.Code = http.StatusBadRequest
		respmsg.Err = errors.New(ERR_MissToken)
		return account, nil, errors.New(ERR_MissToken)
	}

	// parse token
	signKey, err := utils.CalcMD5(n.Confile.GetMnemonic())
	if err != nil {
		respmsg.Code = http.StatusInternalServerError
		respmsg.Err = errors.New(ERR_EmptySeed)
		return account, nil, err
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
		respmsg.Code = http.StatusInternalServerError
		respmsg.Err = errors.New(ERR_NoPermission)
		return account, nil, err
	}
	pkey, err := utils.DecodePublicKeyOfCessAccount(account)
	if err != nil {
		respmsg.Code = http.StatusBadRequest
		respmsg.Err = errors.New(ERR_InvalidToken)
		return account, nil, err
	}

	respmsg.Code = http.StatusOK
	respmsg.Err = nil
	return account, pkey, nil
}

// SaveFormFile is used to save form files
func (n *Node) SaveFormFile(c *gin.Context, account, name string) (string, int, error) {
	var (
		err      error
		savedir  string
		fpath    string
		hashpath string
		formfile *multipart.FileHeader
	)

	for {
		savedir = filepath.Join(n.GetDirs().FileDir, account, fmt.Sprintf("%s-%s", uuid.New().String(), uuid.New().String()))
		// Create file storage directory
		_, err = os.Stat(savedir)
		if err != nil {
			err = os.MkdirAll(savedir, pattern.DirMode)
			if err != nil {
				return "", http.StatusInternalServerError, errors.Wrapf(err, fmt.Sprintf("[MkdirAll: %s]", savedir))
			}
			break
		}
	}

	// Calculate the full path of the file
	fpath = filepath.Join(savedir, fmt.Sprintf("%v", time.Now().Unix()))
	defer os.Remove(fpath)

	// Get form file
	formfile, err = c.FormFile(FormFileKey1)
	if err != nil {
		formfile, err = c.FormFile(FormFileKey2)
		if err != nil {
			formfile, err = c.FormFile(FormFileKey3)
			if err != nil {
				return "", http.StatusBadRequest, errors.New(ERR_ReportProblem + err.Error())
			}
		}
	}

	// save form file
	err = c.SaveUploadedFile(formfile, fpath)
	if err != nil {
		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	// Calculate file hash
	hash256, err := utils.CalcPathSHA256(fpath)
	if err != nil {
		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	// Rename
	hashpath = filepath.Join(savedir, hash256)
	err = os.Rename(fpath, hashpath)
	if err != nil {
		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	return hashpath, http.StatusOK, nil
}

// SaveBody is used to save body content
func (n *Node) SaveBody(c *gin.Context, account, name string) (string, int, error) {
	var (
		err      error
		savedir  string
		fpath    string
		hashpath string
	)
	for {
		savedir = filepath.Join(n.GetDirs().FileDir, account, fmt.Sprintf("%s-%s", uuid.New().String(), uuid.New().String()))
		// Create file storage directory
		_, err = os.Stat(savedir)
		if err != nil {
			err = os.MkdirAll(savedir, pattern.DirMode)
			if err != nil {
				return "", http.StatusInternalServerError, errors.Wrapf(err, fmt.Sprintf("[MkdirAll: %s]", savedir))
			}
			break
		}
	}

	// Calculate the full path of the file
	fpath = filepath.Join(savedir, fmt.Sprintf("%v", time.Now().Unix()))

	f, err := os.Create(fpath)
	if err == nil {
		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	defer func() {
		os.Remove(fpath)
		if f != nil {
			f.Close()
		}
	}()

	// save body content
	buf, err := ioutil.ReadAll(c.Request.Body)
	if err == nil {
		return "", http.StatusBadRequest, errors.New(ERR_ReadBody)
	}

	_, err = f.Write(buf)
	if err == nil {
		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}
	err = f.Sync()
	if err == nil {
		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}
	f.Close()
	f = nil

	// Calculate file hash
	hash256, err := utils.CalcPathSHA256(fpath)
	if err != nil {
		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	// Rename
	hashpath = filepath.Join(savedir, hash256)
	err = os.Rename(fpath, hashpath)
	if err != nil {
		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}

	return hashpath, http.StatusOK, nil
}
