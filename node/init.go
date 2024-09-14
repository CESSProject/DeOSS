/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	out "github.com/CESSProject/DeOSS/common/fout"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/record"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/configs"
	sdkgo "github.com/CESSProject/cess-go-sdk"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func (n *Node) InitNode() *Node {
	n.InitChainClient()
	n.InitWebServer(
		InitMiddlewares(),
		NewHandler(n.Chainer, n.Workspace, n.Logger),
	)
	n.InitMinerRecord(record.NewMinerRecord())
	n.InitLogs()
	return n
}

func (n *Node) InitWebServer(mdls []gin.HandlerFunc, hdl *Handler) {
	gin.SetMode(gin.ReleaseMode)
	n.Engine = gin.Default()
	n.Engine.Use(mdls...)
	hdl.RegisterRoutes(n.Engine)
	go func() {
		err := n.Engine.Run(fmt.Sprintf(":%d", n.Config.Application.Port))
		if err != nil {
			log.Fatal(err)
		}
	}()
}

func InitMiddlewares() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		cors.New(cors.Config{
			AllowAllOrigins: true,
			AllowHeaders: []string{
				HTTPHeader_Bucket,
				HTTPHeader_Territory,
				HTTPHeader_Account,
				HTTPHeader_EthAccount,
				HTTPHeader_Message,
				HTTPHeader_Signature,
				HTTPHeader_Miner,
				HTTPHeader_Longitude,
				HTTPHeader_Latitude,
				HTTPHeader_Fid,
				HTTPHeader_Cipher,
				HTTPHeader_BIdx,
				HTTPHeader_BNum,
				HTTPHeader_Fname,
				HTTPHeader_TSize,
				HTTPHeader_Format,
				HTTPHeader_Range,
				HTTPHeader_X_Forwarded_For,
			},
			AllowMethods: []string{"PUT", "GET", "OPTION"},
		}),
	}
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
		_, err = n.RegisterOss(make([]byte, 0), addr)
		if err != nil {
			return err
		}
		n.RebuildDirs()
		return nil
	}

	if string(ossinfo.Domain[:]) != addr {
		_, err = n.UpdateOss(string(make([]byte, 0)), addr)
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
