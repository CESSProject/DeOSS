/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"log"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/p2p-go/core"
	"github.com/CESSProject/sdk-go/core/sdk"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Oss interface {
	Run()
}

type Node struct {
	confile.Confile
	logger.Logger
	db.Cache
	sdk.SDK
	core.P2P
	*gin.Engine
	TrackDir string
}

// New is used to build a node instance
func New() *Node {
	return &Node{}
}

func (n *Node) Run() {
	gin.SetMode(gin.ReleaseMode)
	n.Engine = gin.Default()
	n.Engine.MaxMultipartMemory = configs.SIZE_1GiB * 16
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AddAllowHeaders(
		configs.Header_Auth,
		configs.Header_Account,
		configs.Header_BucketName,
		"*",
	)
	n.Engine.Use(cors.New(config))
	// Add route
	n.addRoute()
	// Track file
	go n.TrackFile()
	log.Println("Listening on port:", n.GetHttpPort())
	// Run
	err := n.Engine.Run(fmt.Sprintf(":%d", n.GetHttpPort()))
	if err != nil {
		log.Fatalf("err: %v", err)
	}
}
