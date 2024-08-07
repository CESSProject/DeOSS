/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"net/http"

	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func (n *Node) Put_bucket(c *gin.Context) {
	defer c.Request.Body.Close()

	account := c.Request.Header.Get(HTTPHeader_Account)
	if _, ok := <-max_concurrent_req_ch; !ok {
		c.JSON(http.StatusTooManyRequests, "service is busy, please try again later.")
		return
	}
	defer func() { max_concurrent_req_ch <- true }()

	if !checkDeOSSStatus(n, c) {
		return
	}

	clientIp := c.Request.Header.Get("X-Forwarded-For")
	if clientIp == "" {
		clientIp = c.ClientIP()
	}
	bucketName := c.Request.Header.Get(HTTPHeader_Bucket)
	ethAccount := c.Request.Header.Get(HTTPHeader_EthAccount)
	message := c.Request.Header.Get(HTTPHeader_Message)
	signature := c.Request.Header.Get(HTTPHeader_Signature)

	n.Logput("info", utils.StringBuilder(400, clientIp, account, ethAccount, bucketName, message, signature))

	pkey, code, err := verifySignature(n, account, ethAccount, message, signature)
	if err != nil {
		n.Logput("err", clientIp+" verifySignature: "+err.Error())
		c.JSON(code, err)
		return
	}

	if !sutils.CheckBucketName(bucketName) {
		n.Logput("err", clientIp+" CheckBucketName: "+bucketName)
		c.JSON(http.StatusBadRequest, ERR_HeaderFieldBucketName)
		return
	}

	// verify the space is authorized
	code, err = checkAuth(n, pkey)
	if err != nil {
		n.Logput("err", clientIp+" checkAuth: "+err.Error())
		c.JSON(code, err)
		return
	}

	blockHash, err := n.CreateBucket(pkey, bucketName)
	if err != nil {
		n.Logput("err", clientIp+" CreateBucket: "+err.Error())
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	n.Logput("info", clientIp+" create bucket ["+bucketName+"] suc, and the bloack hash is: "+blockHash)

	if len(blockHash) != (chain.FileHashLen + 2) {
		c.JSON(http.StatusOK, "bucket already exists")
	} else {
		c.JSON(http.StatusOK, map[string]string{"block hash:": blockHash})
	}
}

func verifySignature(n *Node, account, ethAccount, message, signature string) ([]byte, int, error) {
	var (
		pkey []byte
		err  error
	)

	if err = n.AccessControl(account); err != nil {
		return nil, http.StatusBadRequest, err
	}

	if ethAccount != "" {
		ethAccInSian, err := VerifyEthSign(message, signature)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		if ethAccInSian != ethAccount {
			return nil, http.StatusBadRequest, errors.New("ETH signature verification failed")
		}
		pkey, err = sutils.ParsingPublickey(account)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		if len(pkey) == 0 {
			return nil, http.StatusBadRequest, errors.New("invalid account")
		}
	} else {
		pkey, err = n.VerifyAccountSignature(account, message, signature)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		if len(pkey) == 0 {
			return nil, http.StatusBadRequest, errors.New("invalid signature")
		}
	}

	return pkey, http.StatusOK, nil
}
