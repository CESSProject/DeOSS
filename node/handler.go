/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/lru"
	"github.com/CESSProject/DeOSS/common/tracker"
	"github.com/CESSProject/DeOSS/common/workspace"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	*FileHandler
	*ResumeHandler
	*ObjectHandler
	*FilesHandler
}

func NewHandler(cli chain.Chainer, track tracker.Tracker, ws workspace.Workspace, lg logger.Logger, cfg *confile.Config, lru *lru.LRUCache) *Handler {
	return &Handler{
		FileHandler:   NewFileHandler(cli, track, ws, lg, cfg, lru),
		ResumeHandler: NewResumeHandler(cli, track, ws, lg, cfg),
		ObjectHandler: NewObjectHandler(cli, track, ws, lg, cfg, lru),
		FilesHandler:  NewFilesHandler(cli, track, ws, lg, cfg, lru),
	}
}

func (h *Handler) RegisterRoutes(server *gin.Engine) {
	h.FileHandler.RegisterRoutes(server)
	h.ResumeHandler.RegisterRoutes(server)
	h.ObjectHandler.RegisterRoutes(server)
	h.FilesHandler.RegisterRoutes(server)
}
