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
	"unsafe"

	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/gin-gonic/gin"
)

type ViewFileType struct {
	FileHash string `json:"file_hash"`
}

// It is used to authorize users
func (n *Node) viewFileListHandle(c *gin.Context) {
	var (
		err error
		req ViewFileType
	)
	if err = c.ShouldBind(&req); err != nil {
		c.JSON(400, "Invalid.FileHash")
		return
	}

	//var hashType chain.FileHash
	if len(req.FileHash) != int(unsafe.Sizeof(chain.FileHash{})) {
		c.JSON(400, "Invalid.FileHash")
		return
	}

	fmeta, err := n.Chain.GetFileMetaInfo(req.FileHash)
	if err != nil {
		c.JSON(400, err.Error())
		return
	}
	c.JSON(http.StatusOK, fmeta)
}
