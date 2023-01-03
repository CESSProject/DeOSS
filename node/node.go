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
	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/CESSProject/cess-oss/pkg/confile"
	"github.com/CESSProject/cess-oss/pkg/db"
	"github.com/CESSProject/cess-oss/pkg/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Oss interface {
	Run()
}

type Node struct {
	Cfile    confile.Confiler
	Chn      chain.Chainer
	Logs     logger.Logger
	Cach     db.Cacher
	Handle   *gin.Engine
	FileDir  string
	TrackDir string
}

// New is used to build a node instance
func New() *Node {
	return &Node{}
}

func (n *Node) Run() {
	gin.SetMode(gin.ReleaseMode)
	n.Handle = gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AddAllowHeaders(
		configs.Header_Auth,
		configs.Header_Account,
		configs.Header_BucketName,
		configs.Header_Digest,
		"*",
	)
	n.Handle.Use(cors.New(config))
	// Add route
	n.addRoute()
	// Track file
	go n.TrackFile()
	// Run
	n.Handle.Run(":" + n.Cfile.GetServicePort())
}
