/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/record"
	"github.com/CESSProject/DeOSS/common/tracker"
	"github.com/CESSProject/DeOSS/common/workspace"
	"github.com/CESSProject/cess-go-sdk/chain"
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
	// tasks
	n.TaskMgt()
}
