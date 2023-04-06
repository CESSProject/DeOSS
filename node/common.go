package node

import (
	"errors"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// VerifyToken is used to parse and verify token
func (n *Node) VerifyToken(c *gin.Context, respmsg *RespMsg) string {
	var (
		ok       bool
		err      error
		tokenstr string
		claims   *CustomClaims
		token    *jwt.Token
		account  string
		signKey  []byte
	)
	if respmsg.Err != nil {
		return account
	}
	// get token from head
	tokenstr = c.Request.Header.Get(Header_Auth)
	if tokenstr == "" {
		respmsg.Code = http.StatusBadRequest
		respmsg.Err = errors.New(ERR_MissToken)
		return account
	}

	// parse token
	signKey, err = utils.CalcMD5(n.Confile.GetMnemonic())
	if err != nil {
		respmsg.Code = http.StatusInternalServerError
		respmsg.Err = errors.New(ERR_EmptySeed)
		return account
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
		return account
	}
	respmsg.Code = http.StatusOK
	respmsg.Err = nil
	return account
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

// SaveBody is used to save body content
func (n *Node) SaveBody(c *gin.Context, account, name string) (int64, string, string, int, error) {
	var (
		err      error
		savedir  string
		fpath    string
		hashpath string
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
		return 0, "", "", http.StatusInternalServerError, errors.New(ERR_DuplicateFileName)
	}

	f, err := os.Create(fpath)
	if err == nil {
		return 0, "", "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
	}
	defer os.Remove(fpath)

	// save body content
	buf, err := ioutil.ReadAll(c.Request.Body)
	if err == nil {
		return 0, "", "", http.StatusBadRequest, errors.New(ERR_ReportProblem + err.Error())
	}

	f.Write(buf)
	f.Sync()
	f.Close()

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
