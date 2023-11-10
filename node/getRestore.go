package node

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// getHandle
func (n *Node) getRestoreHandle(c *gin.Context) {
	var (
		clientIp string
		repeat   bool
		respMsg  = &RespMsg{}
	)

	clientIp = c.ClientIP()
	n.Query("info", fmt.Sprintf("[%s] %s", clientIp, INFO_GetRestoreRequest))

	token := c.Request.Header.Get(HTTPHeader_Authorization)
	account := c.Request.Header.Get(HTTPHeader_Account)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)

	userAccount, _, err := n.verifyToken(token, respMsg)
	if err != nil {
		if account != "" && signature != "" {
			_, err = n.verifySignature(account, message, signature)
			if err != nil {
				n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
				c.JSON(respMsg.Code, err.Error())
				return
			}
		} else {
			n.Upfile("info", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(respMsg.Code, err.Error())
			return
		}
	} else {
		account = userAccount
	}

	if !n.AccessControl(account) {
		n.Upfile("info", fmt.Sprintf("[%v] %v", c.ClientIP(), ERR_Forbidden))
		c.JSON(http.StatusForbidden, ERR_Forbidden)
		return
	}

	var userfils_cache userFiles
	data, err := n.Get([]byte(Cache_UserFiles + account))
	if err == nil {
		json.Unmarshal(data, &userfils_cache)
	}

	var userfils_file userFiles
	data, err = os.ReadFile(filepath.Join(n.ufileDir, account))
	if err == nil {
		err = json.Unmarshal(data, &userfils_file)
	}

	var userDeletedfils_cache userFiles
	data, err = n.Get([]byte(Cache_UserDeleteFiles + account))
	if err == nil {
		json.Unmarshal(data, &userDeletedfils_cache)
	}

	var userDeletedfils_file userFiles
	data, err = os.ReadFile(filepath.Join(n.dfileDir, account))
	if err == nil {
		err = json.Unmarshal(data, &userDeletedfils_file)
	}

	var savedFiles []string
	if userfils_file.User == account {
		savedFiles = append(savedFiles, userfils_file.Files...)
	}
	if userfils_cache.User == account {
		if len(userfils_cache.Files) > 0 {
			for i := 0; i < len(userfils_cache.Files); i++ {
				repeat = false
				for j := 0; j < len(userfils_file.Files); j++ {
					if userfils_cache.Files[i] == userfils_file.Files[j] {
						repeat = true
						break
					}
				}
				if !repeat {
					savedFiles = append(savedFiles, userfils_cache.Files[i])
				}
			}
		}
	}
	var deletedFiles []string
	if userDeletedfils_file.User == account {
		deletedFiles = append(deletedFiles, userDeletedfils_file.Files...)
	}
	if userDeletedfils_cache.User == account {
		for i := 0; i < len(userDeletedfils_cache.Files); i++ {
			repeat = false
			for j := 0; j < len(userDeletedfils_file.Files); j++ {
				if userDeletedfils_cache.Files[i] == userDeletedfils_file.Files[i] {
					repeat = true
					break
				}
			}
			if !repeat {
				deletedFiles = append(deletedFiles, userDeletedfils_cache.Files[i])
			}
		}
	}

	var result = userFiles{
		User:  account,
		Files: []string{},
	}

	for i := 0; i < len(savedFiles); i++ {
		repeat = false
		for j := 0; j < len(deletedFiles); j++ {
			if savedFiles[i] == deletedFiles[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			result.Files = append(result.Files, savedFiles[i])
		}
	}

	c.JSON(http.StatusOK, result)
}
