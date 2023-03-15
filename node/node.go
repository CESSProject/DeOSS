/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"log"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/chain"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Oss interface {
	Run()
}

type Node struct {
	Confile  confile.Confiler
	Chain    chain.Chainer
	Logs     logger.Logger
	Cache    db.Cacher
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
	n.Handle.MaxMultipartMemory = configs.SIZE_1GiB * 16
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AddAllowHeaders(
		configs.Header_Auth,
		configs.Header_Account,
		configs.Header_BucketName,
		"*",
	)
	n.Handle.Use(cors.New(config))
	// Add route
	n.addRoute()
	// Track file
	go n.TrackFile()
	log.Println("Listening on port :", n.Confile.GetServicePort())
	// Run
	n.Handle.Run(":" + n.Confile.GetServicePort())
}
