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
	"net/http"

	"github.com/CESSProject/cess-oss/pkg/utils"
	"github.com/gin-gonic/gin"
)

type ViewBucketType struct {
	Account    string `json:"account"`
	BucketName string `json:"bucket_name"`
}

// It is used to authorize users
func (n *Node) viewBucketHandle(c *gin.Context) {
	var (
		err error
		req ViewBucketType
	)

	if err = c.ShouldBind(&req); err != nil {
		c.JSON(400, "Invalid.Body")
		return
	}

	if !VerifyBucketName(req.BucketName) {
		c.JSON(400, "InvalidParameter.BucketName")
		return
	}

	pkey, err := utils.DecodePublicKeyOfCessAccount(req.Account)
	if err != nil {
		c.JSON(400, "InvalidParameter.Account")
		return
	}

	bucketInfo, err := n.Chain.GetBucketInfo(pkey, req.BucketName)
	if err != nil {
		c.JSON(400, err.Error())
		return
	}
	filesHash := make([]string, len(bucketInfo.Objects_list))
	for i := 0; i < len(bucketInfo.Objects_list); i++ {
		filesHash[i] = string(bucketInfo.Objects_list[i][:])
	}
	data := struct {
		Num   uint32
		Files []string
	}{
		Num:   uint32(bucketInfo.Objects_num),
		Files: filesHash,
	}
	c.JSON(http.StatusOK, data)
}
