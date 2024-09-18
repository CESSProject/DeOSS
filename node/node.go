/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"
	"log"

	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/record"
	"github.com/CESSProject/DeOSS/common/tracker"
	"github.com/CESSProject/DeOSS/common/workspace"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/CESSProject/p2p-go/out"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Node struct {
	*confile.Config
	*gin.Engine
	chain.Chainer
	workspace.Workspace
	logger.Logger
	record.MinerRecorder
	tracker.Tracker
}

func NewEmptyNode() *Node {
	return &Node{}
}

func NewNodeWithConfig(cfg *confile.Config) *Node {
	return &Node{Config: cfg}
}

func (n *Node) InitChainclient(cli chain.Chainer) {
	n.Chainer = cli
}

func (n *Node) InitWorkspace(ws string) {
	n.Workspace = workspace.NewWorkspace(ws)
}

func (n *Node) InitLogger(lg logger.Logger) {
	n.Logger = lg
}

func (n *Node) InitMinerRecord(r record.MinerRecorder) {
	n.MinerRecorder = r
}

func (n *Node) InitTracker(t tracker.Tracker) {
	n.Tracker = t
}

func (n *Node) InitServer(s *gin.Engine) {
	n.Engine = s
}

func (n *Node) Start() {
	gin.SetMode(n.Config.Application.Mode)
	n.Engine = gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AddAllowHeaders("*")
	config.AddExposeHeaders("*")
	n.Engine.MaxMultipartMemory = MaxMemUsed
	n.Engine.Use(cors.New(config))

	n.Engine.GET("/version", n.Get_version)
	n.Engine.GET("/bucket", n.Get_bucket)
	n.Engine.GET(fmt.Sprintf("/metadata/:%s", HTTP_ParameterName_Fid), n.GetFileMetadata)
	n.Engine.GET(fmt.Sprintf("/download/:%s", HTTP_ParameterName_Fid), n.DownloadFile)
	n.Engine.GET(fmt.Sprintf("/canfiles/:%s", HTTP_ParameterName_Fid), n.GetCanFileHandle)
	n.Engine.GET(fmt.Sprintf("/open/:%s", HTTP_ParameterName_Fid), n.PreviewFile)
	n.Engine.GET(fmt.Sprintf("/location/:%s", HTTP_ParameterName_Fid), n.GetFileLocation)

	n.Engine.PUT("/bucket", n.PutBucket)
	n.Engine.PUT("/file", n.PutFile)
	n.Engine.PUT("/object", n.PutObject)
	n.Engine.PUT(fmt.Sprintf("/resume/:%s", HTTP_ParameterName), n.ResumeUpload)
	n.Engine.PUT("/chunks", n.PutChunksHandle)

	n.Engine.DELETE(fmt.Sprintf("/file/:%s", HTTP_ParameterName), n.DeleteFile)
	n.Engine.DELETE(fmt.Sprintf("/bucket/:%s", HTTP_ParameterName), n.DeleteBucket)

	n.Engine.GET("/favicon.ico", func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=31536000")
		c.File("./static/favicon.ico")
	})

	// tasks
	go n.TaskMgt()

	out.Tip(fmt.Sprintf("Listening on port: %d", n.Config.Application.Port))
	err := n.Engine.Run(fmt.Sprintf(":%d", n.Config.Application.Port))
	if err != nil {
		log.Fatalf("err: %v", err)
	}
}
