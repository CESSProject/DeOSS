/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/tracker"
	"github.com/CESSProject/DeOSS/common/workspace"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	*FileHandler
	//*StatusHandler
}

func NewHandler(cli chain.Chainer, track tracker.Tracker, ws workspace.Workspace, lg logger.Logger) *Handler {
	return &Handler{
		FileHandler: NewFileHandler(cli, track, ws, lg),
		//StatusHandler:   NewStatusHandler(rs),
	}
}

func (h *Handler) RegisterRoutes(server *gin.Engine) {
	h.FileHandler.RegisterRoutes(server)
	//h.StatusHandler.RegisterRoutes(server)
}
