package node

import (
	"net/http"

	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/disk"
)

// VerifyToken is used to parse and verify token
func (n *Node) verifyToken(token string, respmsg *RespMsg) (string, []byte, error) {
	var (
		ok       bool
		err      error
		claims   *CustomClaims
		jwttoken *jwt.Token
		account  string
	)

	if respmsg.Err != nil {
		return account, nil, err
	}

	if token == "" {
		respmsg.Code = http.StatusForbidden
		respmsg.Err = errors.New(ERR_Authorization)
		return account, nil, respmsg.Err
	}

	// parse token
	jwttoken, err = jwt.ParseWithClaims(
		token,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return n.signkey, nil
		})

	if claims, ok = jwttoken.Claims.(*CustomClaims); ok && jwttoken.Valid {
		account = claims.Account
	} else {
		respmsg.Code = http.StatusForbidden
		respmsg.Err = errors.New(ERR_NoPermission)
		return account, nil, err
	}
	pkey, err := sutils.ParsingPublickey(account)
	if err != nil {
		respmsg.Code = http.StatusBadRequest
		respmsg.Err = errors.New(ERR_InvalidToken)
		return account, nil, err
	}

	respmsg.Code = http.StatusOK
	respmsg.Err = nil
	return account, pkey, nil
}

// 判断挂载目录
func judgeMountPath(mountpath string, addspace uint64) (bool, error) {
	var availabeStorage []struct {
		Path  string
		Total uint64
		Free  uint64
	}

	//获取磁盘分区
	pss, err := disk.Partitions(false)
	if err != nil {
		return false, errors.Wrapf(err, "[disk.Partitions]")
	}

	for _, ps := range pss {
		// Usage返回文件系统的使用情况。Path是文件系统路径，如“/”，而不是设备文件路径，如“/dev/vda1”。如果要使用磁盘返回值。分区，使用“挂载点”而不是“设备”。
		us, err := disk.Usage(ps.Mountpoint)
		if err != nil {
			continue
		}
		//磁盘空间最小限制500G
		if us.Total < 500 {
			continue
		} else {
			ab := struct {
				Path  string
				Total uint64
				Free  uint64
			}{
				Path:  us.Path,
				Total: us.Total,
				Free:  us.Free,
			}
			availabeStorage = append(availabeStorage, ab)
		}
	}
	return true, nil
}

// SaveFormFile is used to save form files
// func (n *Node) SaveFormFile(c *gin.Context, account, name string) (string, int, error) {
// 	var (
// 		err      error
// 		savedir  string
// 		fpath    string
// 		hashpath string
// 		formfile *multipart.FileHeader
// 	)

// 	for {
// 		savedir = filepath.Join(n.GetDirs().FileDir, account, fmt.Sprintf("%s-%s", uuid.New().String(), uuid.New().String()))
// 		// Create file storage directory
// 		_, err = os.Stat(savedir)
// 		if err != nil {
// 			err = os.MkdirAll(savedir, pattern.DirMode)
// 			if err != nil {
// 				return "", http.StatusInternalServerError, errors.Wrapf(err, fmt.Sprintf("[MkdirAll: %s]", savedir))
// 			}
// 			break
// 		}
// 	}

// 	// Calculate the full path of the file
// 	fpath = filepath.Join(savedir, fmt.Sprintf("%v", time.Now().Unix()))
// 	defer os.Remove(fpath)

// 	// Get form file
// 	formfile, err = c.FormFile(FormFileKey1)
// 	if err != nil {
// 		formfile, err = c.FormFile(FormFileKey2)
// 		if err != nil {
// 			formfile, err = c.FormFile(FormFileKey3)
// 			if err != nil {
// 				return "", http.StatusBadRequest, errors.New(ERR_ReportProblem + err.Error())
// 			}
// 		}
// 	}

// 	// save form file
// 	err = c.SaveUploadedFile(formfile, fpath)
// 	if err != nil {
// 		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
// 	}

// 	// Calculate file hash
// 	hash256, err := utils.CalcPathSHA256(fpath)
// 	if err != nil {
// 		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
// 	}

// 	// Rename
// 	hashpath = filepath.Join(savedir, hash256)
// 	err = os.Rename(fpath, hashpath)
// 	if err != nil {
// 		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
// 	}

// 	return hashpath, http.StatusOK, nil
// }

// SaveBody is used to save body content
// func (n *Node) SaveBody(c *gin.Context, account, name string) (string, int, error) {
// 	var (
// 		err      error
// 		savedir  string
// 		fpath    string
// 		hashpath string
// 	)
// 	for {
// 		savedir = filepath.Join(n.GetDirs().FileDir, account, fmt.Sprintf("%s-%s", uuid.New().String(), uuid.New().String()))
// 		// Create file storage directory
// 		_, err = os.Stat(savedir)
// 		if err != nil {
// 			err = os.MkdirAll(savedir, pattern.DirMode)
// 			if err != nil {
// 				return "", http.StatusInternalServerError, errors.Wrapf(err, fmt.Sprintf("[MkdirAll: %s]", savedir))
// 			}
// 			break
// 		}
// 	}

// 	// Calculate the full path of the file
// 	fpath = filepath.Join(savedir, fmt.Sprintf("%v", time.Now().Unix()))

// 	f, err := os.Create(fpath)
// 	if err == nil {
// 		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
// 	}

// 	defer func() {
// 		os.Remove(fpath)
// 		if f != nil {
// 			f.Close()
// 		}
// 	}()

// 	// save body content
// 	buf, err := ioutil.ReadAll(c.Request.Body)
// 	if err == nil {
// 		return "", http.StatusBadRequest, errors.New(ERR_ReadBody)
// 	}

// 	_, err = f.Write(buf)
// 	if err == nil {
// 		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
// 	}
// 	err = f.Sync()
// 	if err == nil {
// 		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
// 	}
// 	f.Close()
// 	f = nil

// 	// Calculate file hash
// 	hash256, err := utils.CalcPathSHA256(fpath)
// 	if err != nil {
// 		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
// 	}

// 	// Rename
// 	hashpath = filepath.Join(savedir, hash256)
// 	err = os.Rename(fpath, hashpath)
// 	if err != nil {
// 		return "", http.StatusInternalServerError, errors.New(ERR_ReportProblem + err.Error())
// 	}

// 	return hashpath, http.StatusOK, nil
// }
