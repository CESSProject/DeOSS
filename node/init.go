/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	out "github.com/CESSProject/DeOSS/common/fout"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/lru"
	"github.com/CESSProject/DeOSS/common/record"
	"github.com/CESSProject/DeOSS/common/tracker"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/configs"
	sdkgo "github.com/CESSProject/cess-go-sdk"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

//go:embed favicon.ico
var favicon string

func (n *Node) InitNode() *Node {
	n.InitChainClient()
	n.InitMinerRecord(record.NewMinerRecord())
	n.InitTracker(tracker.NewTracker(n.GetTrackDir()))
	n.InitLogs()
	n.InitCache()
	n.InitWebServer(
		InitMiddlewares(),
		NewHandler(n.Chainer, n.Tracker, n.Workspace, n.Logger, n.Config, n.LRUCache),
	)
	return n
}

func (n *Node) InitWebServer(mdls []gin.HandlerFunc, hdl *Handler) {
	gin.SetMode(n.Config.Application.Mode)
	server := gin.Default()
	server.Use(mdls...)
	server.GET("/favicon.ico", func(ctx *gin.Context) {
		ctx.Header("Cache-Control", "public, max-age=31536000")
		ctx.Data(200, "image/x-icon", []byte(favicon))
	})
	server.GET("/version", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, configs.Version)
	})
	hdl.RegisterRoutes(server)
	go func() {
		err := server.Run(fmt.Sprintf(":%d", n.Config.Application.Port))
		if err != nil {
			log.Fatal(err)
		}
	}()
	n.InitServer(server)
}

func InitMiddlewares() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		cors.New(cors.Config{
			//AllowAllOrigins: true,
			AllowHeaders: []string{"*"},
			// AllowHeaders: []string{
			// 	HTTPHeader_Territory,
			// 	HTTPHeader_Account,
			// 	HTTPHeader_EthAccount,
			// 	HTTPHeader_Message,
			// 	HTTPHeader_Signature,
			// 	HTTPHeader_Miner,
			// 	HTTPHeader_Longitude,
			// 	HTTPHeader_Latitude,
			// 	HTTPHeader_Fid,
			// 	HTTPHeader_Cipher,
			// 	HTTPHeader_Filename,
			// 	HTTPHeader_Format,
			// 	HTTPHeader_Range,
			// 	HTTPHeader_X_Forwarded_For,
			// },
			AllowMethods: []string{"PUT", "GET", "DELETE", "OPTION"},
			AllowOriginFunc: func(origin string) bool {
				return true
			},
		}),
	}
}

func (n *Node) InitCache() {
	lru := lru.NewLRUCache(n.Config.Maxusespace)
	err := lru.InitCheck(n.GetFileDir())
	if err != nil {
		out.Err("Check cache failed.")
		os.Exit(1)
	}
	n.InitLRUCache(lru)
}

func (n *Node) InitLogs() {
	var logs_info = make(map[string]string)
	for _, v := range logger.LogFiles {
		logs_info[v] = filepath.Join(n.GetLogDir(), v+".log")
	}
	lg, err := logger.NewLogs(logs_info)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}
	n.InitLogger(lg)
}

func (n *Node) InitChainClient() {
	cli, err := sdkgo.New(
		context.Background(),
		sdkgo.Name(configs.Name),
		sdkgo.ConnectRpcAddrs(n.Config.Chain.Rpc),
		sdkgo.Mnemonic(n.Config.Chain.Mnemonic),
		sdkgo.TransactionTimeout(time.Second*time.Duration(n.Config.Chain.Timeout)),
	)
	if err != nil {
		out.Err(fmt.Sprintf("[sdkgo.New] %v", err))
		os.Exit(1)
	}

	n.InitChainclient(cli)
	n.InitWorkspace(filepath.Join(n.Config.Application.Workspace, n.GetSignatureAcc(), configs.Name))

	err = checkRpcSynchronization(cli)
	if err != nil {
		out.Err("Failed to sync block: network error")
		os.Exit(1)
	}

	err = n.InitExtrinsicsNameForOSS()
	if err != nil {
		out.Err("The rpc address does not match the software version, please check the rpc address.")
		os.Exit(1)
	}

	addr := ""
	if n.Config.Visibility == configs.Access_Public {
		addr = n.Config.Domainname
		if addr == "" {
			publicip, err := utils.GetPublicIP()
			if err == nil {
				addr = fmt.Sprintf("%s:%d", publicip, n.Config.Application.Port)
			}
		}
	}

	err = n.checkOss(addr)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}
}

func (n Node) checkOss(addr string) error {
	ossinfo, err := n.QueryOss(n.GetSignatureAccPulickey(), -1)
	if err != nil {
		if err.Error() != chain.ERR_Empty {
			return err
		}
		_, err = n.RegisterOss(addr)
		if err != nil {
			return err
		}
		n.RemoveAndBuild()
		return nil
	}

	n.Build()
	if string(ossinfo.Domain[:]) != addr {
		_, err = n.UpdateOss(addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkRpcSynchronization(cli chain.Chainer) error {
	out.Tip("Waiting to synchronize the main chain...")
	var err error
	var syncSt chain.SysSyncState
	for {
		syncSt, err = cli.SystemSyncState()
		if err != nil {
			return err
		}
		if syncSt.CurrentBlock == syncSt.HighestBlock {
			out.Ok(fmt.Sprintf("Synchronization the main chain completed: %d", syncSt.CurrentBlock))
			break
		}
		out.Tip(fmt.Sprintf("In the synchronization main chain: %d ...", syncSt.CurrentBlock))
		time.Sleep(time.Second * time.Duration(utils.Ternary(int64(syncSt.HighestBlock-syncSt.CurrentBlock)*6, 30)))
	}
	return nil
}
