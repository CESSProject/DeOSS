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

type AuthType struct {
	Account   []byte
	Signature []byte
	Message   string
}

// It is used to authorize users
func (n *Node) authHandle(c *gin.Context) {
	var (
		err error
		req AuthType
	)
	if err = c.ShouldBind(&req); err != nil {
		c.JSON(400, "Invalid.Body")
		return
	}

	// Check publickey
	if err = utils.VerityAddress(string(req.Account), utils.CessPrefix); err != nil {
		c.JSON(400, "InvalidParameter.Account")
		return
	}

	if req.Message == "" {
		c.JSON(400, "InvalidParameter.Message")
		return
	}

	if len(req.Signature) == 0 {
		c.JSON(400, "InvalidParameter.Signature")
		return
	}

	c.JSON(http.StatusOK, "")
	return
}
