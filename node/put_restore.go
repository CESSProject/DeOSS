package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	sconfig "github.com/CESSProject/cess-go-sdk/config"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
)

type RestoreList struct {
	Files []string `json:"files"`
}

// getHandle
func (n *Node) RestoreFile(c *gin.Context) {
	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" || clientIp == " " {
		clientIp = c.ClientIP()
	}
	n.Log("info", fmt.Sprintf("[%s] %s", clientIp, INFO_PostRestoreRequest))
	var err error
	var pkey []byte
	account := c.Request.Header.Get(HTTPHeader_Account)
	territoryName := c.Request.Header.Get(HTTPHeader_Territory)
	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)

	if err = n.AccessControl(account); err != nil {
		n.Log("info", fmt.Sprintf("[%v] %v", clientIp, err))
		c.JSON(http.StatusForbidden, err.Error())
		return
	}

	if ethAccount != "" {
		ethAccInSian, err := VerifyEthSign(message, signature)
		if err != nil {
			n.Log("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
		if ethAccInSian != ethAccount {
			n.Log("err", fmt.Sprintf("[%v] %s", clientIp, "ETH signature verification failed"))
			c.JSON(http.StatusBadRequest, "ETH signature verification failed")
			return
		}
		pkey, err = sutils.ParsingPublickey(account)
		if err != nil {
			n.Log("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, fmt.Sprintf("invalid cess account: %s", account))
			return
		}
	} else {
		pkey, err = n.VerifyAccountSignature(account, message, signature)
		if err != nil {
			n.Log("err", fmt.Sprintf("[%v] %s", clientIp, err.Error()))
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
	}

	var restoreList RestoreList
	err = c.ShouldBind(&restoreList)
	if err != nil {
		n.Log("err", fmt.Sprintf("[%v] [ShouldBind] %v", clientIp, err))
		c.JSON(400, "InvalidBody.RestoreFiles")
		return
	}

	if len(restoreList.Files) == 0 {
		n.Log("err", fmt.Sprintf("[%v] The restored file is empty", clientIp))
		c.JSON(400, errors.New("the restored file is empty"))
		return
	}

	n.Log("info", fmt.Sprintf("[%v] restored files: %v", clientIp, restoreList.Files))

	// verify the bucket name
	bucketName := c.Request.Header.Get(HTTPHeader_Bucket)
	if !sutils.CheckBucketName(bucketName) {
		n.Log("info", fmt.Sprintf("[%v] %v", clientIp, ERR_HeaderFieldBucketName))
		c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
		return
	}

	// verify the space is authorized
	var flag bool
	authAccs, _ := n.QueryAuthorityList(pkey, -1)
	for _, v := range authAccs {
		if sutils.CompareSlice(n.GetSignatureAccPulickey(), v[:]) {
			flag = true
			break
		}
	}
	if !flag {
		n.Log("info", fmt.Sprintf("[%v] %v", clientIp, ERR_SpaceNotAuth))
		c.JSON(http.StatusForbidden, ERR_SpaceNotAuth)
		return
	}

	var allUsedSpace int64
	var count int64
	for i := 0; i < len(restoreList.Files); i++ {
		fstat, err := os.Stat(filepath.Join(n.fileDir, restoreList.Files[i]))
		if err != nil {
			continue
		}

		count = fstat.Size() / sconfig.SegmentSize
		if fstat.Size()%sconfig.SegmentSize != 0 {
			count += 1
		}
		allUsedSpace += (count * sconfig.SegmentSize)
	}

	code, err := checkSapce(n, pkey, territoryName, allUsedSpace, 1000)
	if err != nil {
		n.Log("info", fmt.Sprintf("[%v] %v", clientIp, ERR_AccountNotExist))
		c.JSON(code, err)
		return
	}

	for i := 0; i < len(restoreList.Files); i++ {
		fstat, err := os.Stat(filepath.Join(n.fileDir, restoreList.Files[i]))
		if err != nil {
			continue
		}
		var recordInfo = &TrackerInfo{
			Segment:       nil,
			Owner:         pkey,
			Fid:           restoreList.Files[i],
			FileName:      "empty",
			BucketName:    bucketName,
			TerritoryName: territoryName,
			FileSize:      uint64(fstat.Size()),
			PutFlag:       false,
		}

		b, err := json.Marshal(recordInfo)
		if err != nil {
			n.Log("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			continue
		}

		err = n.WriteTrackFile(restoreList.Files[i], b)
		if err != nil {
			n.Log("err", fmt.Sprintf("[%v] %v", clientIp, err))
			c.JSON(http.StatusInternalServerError, ERR_InternalServer)
			continue
		}
	}
}
