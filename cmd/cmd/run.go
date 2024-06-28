/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/DeOSS/pkg/utils"
	cess "github.com/CESSProject/cess-go-sdk"
	"github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/CESSProject/cess-go-tools/scheduler"
	p2pgo "github.com/CESSProject/p2p-go"
	"github.com/CESSProject/p2p-go/core"
	"github.com/CESSProject/p2p-go/out"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/howeyc/gopass"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// cmd_run_func is an implementation of the run command,
// which is used to start the deoss service.
func cmd_run_func(cmd *cobra.Command, args []string) {
	var (
		registerFlag bool
		err          error
		logDir       string
		dbDir        string
		trackDir     string
		fadebackDir  string
		ufileDir     string
		dfileDir     string
		syncSt       chain.SysSyncState
		peerRecord   = node.NewPeerRecord()
		n            = node.New()
	)
	ctx := cmd.Context()
	// Building Profile Instances
	n.Confile, err = buildConfigFile(cmd)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}

	if !core.FreeLocalPort(uint32(n.GetHttpPort())) {
		out.Err(fmt.Sprintf("port [%d] is in use", n.GetHttpPort()))
		os.Exit(1)
	}

	signKey, err := sutils.CalcMD5(n.Confile.GetMnemonic())
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}

	n.SetSignkey(signKey)

	// Build sdk
	n.ChainClient, err = cess.New(
		ctx,
		cess.Name(configs.Name),
		cess.ConnectRpcAddrs(n.GetRpcAddr()),
		cess.Mnemonic(n.GetMnemonic()),
		cess.TransactionTimeout(configs.TimeOut_WaitBlock),
	)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}
	defer n.ChainClient.Close()

	for {
		syncSt, err = n.SystemSyncState()
		if err != nil {
			out.Err(err.Error())
			os.Exit(1)
		}
		if syncSt.CurrentBlock == syncSt.HighestBlock {
			out.Tip(fmt.Sprintf("Synchronization main chain completed: %d", syncSt.CurrentBlock))
			break
		}
		out.Tip(fmt.Sprintf("In the synchronization main chain: %d ...", syncSt.CurrentBlock))
		time.Sleep(time.Second * time.Duration(utils.Ternary(int64(syncSt.HighestBlock-syncSt.CurrentBlock)*6, 30)))
	}

	ossinfo, err := n.QueryOss(n.GetSignatureAccPulickey(), -1)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			registerFlag = true
		} else {
			out.Err("Weak network signal or rpc service failure")
			os.Exit(1)
		}
	}

	n.PeerNode, err = p2pgo.New(
		ctx,
		p2pgo.ListenPort(n.GetP2pPort()),
		p2pgo.Workspace(filepath.Join(n.GetWorkspace(), n.GetSignatureAcc(), configs.Name)),
		p2pgo.BootPeers(n.GetBootNodes()),
	)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}
	defer n.PeerNode.Close()

	go node.Subscribe(
		ctx, n.PeerNode.GetHost(),
		n.PeerNode.GetBootnode(),
		func(p peer.AddrInfo) {
			peerRecord.SavePeer(p)
			if n.HasStoragePeer(p.ID.String()) {
				n.FlushPeerNodes(scheduler.DEFAULT_TIMEOUT, p)
			}
		},
	)
	time.Sleep(time.Second)

	out.Tip(fmt.Sprintf("chain network: %s", n.GetNetworkEnv()))

	if registerFlag {
		_, err = n.RegisterOss(n.GetPeerPublickey(), n.GetDomainName())
		if err != nil {
			out.Err(fmt.Sprintf("register deoss err: %v", err))
			os.Exit(1)
		}
		n.RebuildDirs()
	} else {
		newPeerid := n.GetPeerPublickey()
		if !sutils.CompareSlice([]byte(string(ossinfo.Peerid[:])), newPeerid) ||
			n.GetDomainName() != string(ossinfo.Domain) {
			txhash, err := n.UpdateOss(string(newPeerid), n.GetDomainName())
			if err != nil {
				out.Err(fmt.Sprintf("[%s] update deoss err: %v", txhash, err))
				os.Exit(1)
			}
		}
	}

	logDir, dbDir, trackDir, fadebackDir, ufileDir, dfileDir, err = buildDir(n.Workspace())
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}
	n.SetTrackDir(trackDir)
	n.SetFadebackDir(fadebackDir)
	n.SetUfileDir(ufileDir)
	n.SetDfileDir(dfileDir)

	//init DeOSS extension components
	cacheDir := n.Confile.GetCacheDir()
	if cacheDir == "" {
		cacheDir = filepath.Join(n.Workspace(), configs.FILE_CACHE)
	}
	n.InitFileCache(
		time.Duration(n.Confile.GetCacheItemExp()),
		n.Confile.GetCacheSize(),
		cacheDir,
	)
	nodeFilePath := n.Confile.GetNodeFilePath()
	if nodeFilePath == "" {
		nodeFilePath = filepath.Join(n.Workspace(), "storage_nodes.json")
	}
	n.InitNodeSelector(
		n.Confile.GetSelectStrategy(),
		nodeFilePath,
		n.Confile.GetMaxNodeNum(),
		n.Confile.GetMaxTTL(),
		n.Confile.GetRefreshTime(),
	)

	// Build cache
	n.Cache, err = buildCache(dbDir)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}

	// Build Log
	n.Logger, err = buildLogs(logDir)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}

	n.PeerRecord = peerRecord
	out.Tip(n.Workspace())

	server, err := buildHttpServer(n)
	if err != nil {
		log.Fatalf("[buildHttpServer] %v", err)
	}
	go func() {
		if err = server.ListenAndServe(); err != nil {
			log.Fatalf("[ListenAndServe] %v", err)
		}
	}()

	// tasks
	go n.TaskMgt()

	out.Tip(fmt.Sprintf("Listening on port: %d", n.GetHttpPort()))

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Println("Received an exit signal: ", sig.String())

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
	}
	log.Println("Server has exited")
}

func buildConfigFile(cmd *cobra.Command) (confile.Confile, error) {
	var conFilePath string
	configpath1, _ := cmd.Flags().GetString("config")
	configpath2, _ := cmd.Flags().GetString("c")
	if configpath1 != "" {
		_, err := os.Stat(configpath1)
		if err != nil {
			return nil, errors.Wrapf(err, "[Stat %s]", configpath1)
		}
		conFilePath = configpath1
	} else if configpath2 != "" {
		_, err := os.Stat(configpath2)
		if err != nil {
			return nil, errors.Wrapf(err, "[Stat %s]", configpath2)
		}
		conFilePath = configpath2
	} else {
		conFilePath = configs.DefaultConfig
	}

	cfg := confile.NewConfigfile()
	err := cfg.Parse(conFilePath)
	if err == nil {
		return cfg, nil
	}

	rpc, err := cmd.Flags().GetStringSlice("rpc")
	if err != nil {
		return cfg, errors.Wrapf(err, "[cmd.Flags().GetStringSlice(\"rpc\")]")
	}

	if len(rpc) == 0 {
		return cfg, errors.New("Please specify the rpc address with --rpc")
	}
	cfg.SetRpcAddr(rpc)

	boot, err := cmd.Flags().GetStringSlice("boot")
	if err != nil {
		return cfg, errors.Wrapf(err, "[cmd.Flags().GetStringSlice(\"boot\")]")
	}
	if len(boot) == 0 {
		return cfg, errors.New("Please specify the boot node address with --boot")
	}
	cfg.SetBootNodes(boot)

	workspace, err := cmd.Flags().GetString("ws")
	if err != nil {
		return cfg, err
	}
	if workspace == "" {
		return cfg, errors.New("Please specify the sorkspace with --ws")
	}
	err = cfg.SetWorkspace(workspace)
	if err != nil {
		return cfg, errors.Wrapf(err, "[SetWorkspace %s]", workspace)
	}

	http_port, err := cmd.Flags().GetInt("http_port")
	if err != nil {
		return cfg, errors.Wrapf(err, "[cmd.Flags().GetInt(\"http_port\")]")
	}

	p2p_port, err := cmd.Flags().GetInt("p2p_port")
	if err != nil {
		return cfg, errors.Wrapf(err, "[cmd.Flags().GetInt(\"p2p_port\")]")
	}

	err = cfg.SetHttpPort(http_port)
	if err != nil {
		return cfg, errors.Wrapf(err, "[SetHttpPort %d]", http_port)
	}
	err = cfg.SetP2pPort(p2p_port)
	if err != nil {
		return cfg, errors.Wrapf(err, "[SetP2pPort %d]", p2p_port)
	}

	mnemonic, err := cmd.Flags().GetString("mnemonic")
	if err != nil {
		return cfg, errors.Wrapf(err, "[cmd.Flags().GetString(\"mnemonic\")]")
	}
	if mnemonic == "" {
		out.Input("Please enter the mnemonic of the staking account:")
		for {
			pwd, err := gopass.GetPasswdMasked()
			if err != nil {
				if err.Error() == "interrupted" || err.Error() == "interrupt" || err.Error() == "killed" {
					os.Exit(0)
				}
				out.Input("Invalid mnemonic, please check and re-enter:")
				continue
			}
			if len(pwd) == 0 {
				out.Input("The mnemonic you entered is empty, please re-enter:")
				continue
			}
			err = cfg.SetMnemonic(string(pwd))
			if err != nil {
				out.Input("Invalid mnemonic, please check and re-enter:")
				continue
			}
			break
		}
	} else {
		err = cfg.SetMnemonic(mnemonic)
		if err != nil {
			return cfg, errors.Wrapf(err, "[SetMnemonic] [%s]", mnemonic)
		}
	}
	return cfg, nil
}

func buildAuthenticationConfig(cmd *cobra.Command) (confile.Confile, error) {
	var conFilePath string
	configpath1, _ := cmd.Flags().GetString("config")
	configpath2, _ := cmd.Flags().GetString("c")
	if configpath1 != "" {
		conFilePath = configpath1
	} else if configpath2 != "" {
		conFilePath = configpath2
	} else {
		conFilePath = configs.DefaultConfig
	}

	cfg := confile.NewConfigfile()
	err := cfg.Parse(conFilePath)
	if err == nil {
		return cfg, err
	}

	rpc, err := cmd.Flags().GetStringSlice("rpc")
	if err != nil {
		return cfg, err
	}
	cfg.SetRpcAddr(rpc)

	out.Input("Please enter the mnemonic of the staking account:")
	for {
		pwd, err := gopass.GetPasswdMasked()
		if err != nil {
			if err.Error() == "interrupted" || err.Error() == "interrupt" || err.Error() == "killed" {
				os.Exit(0)
			}
			out.Input("Invalid mnemonic, please check and re-enter:")
			continue
		}
		if len(pwd) == 0 {
			out.Input("The mnemonic you entered is empty, please re-enter:")
			continue
		}
		err = cfg.SetMnemonic(string(pwd))
		if err != nil {
			out.Input("Invalid mnemonic, please check and re-enter:")
			continue
		}
		break
	}
	return cfg, nil
}

func buildDir(workspace string) (string, string, string, string, string, string, error) {
	logDir := filepath.Join(workspace, configs.Log)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", "", "", "", "", "", err
	}

	cacheDir := filepath.Join(workspace, configs.Db)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", "", "", "", "", "", err
	}

	trackDir := filepath.Join(workspace, configs.Track)
	if err := os.MkdirAll(trackDir, 0755); err != nil {
		return "", "", "", "", "", "", err
	}

	feedbackDir := filepath.Join(workspace, configs.Feedback)
	if err := os.MkdirAll(feedbackDir, 0755); err != nil {
		return "", "", "", "", "", "", err
	}

	ufileDir := filepath.Join(workspace, configs.Ufile)
	if err := os.MkdirAll(ufileDir, 0755); err != nil {
		return "", "", "", "", "", "", err
	}
	dfileDir := filepath.Join(workspace, configs.Dfile)
	if err := os.MkdirAll(dfileDir, 0755); err != nil {
		return "", "", "", "", "", "", err
	}

	//make file cache dir
	fileCache := filepath.Join(workspace, configs.FILE_CACHE)
	if err := os.MkdirAll(fileCache, 0755); err != nil {
		return "", "", "", "", "", "", err
	}
	return logDir, cacheDir, trackDir, feedbackDir, ufileDir, dfileDir, nil
}

func buildCache(cacheDir string) (db.Cache, error) {
	return db.NewCache(cacheDir, 0, 0, configs.NameSpace)
}

func buildLogs(logDir string) (logger.Logger, error) {
	var logs_info = make(map[string]string)
	for _, v := range logger.LogFiles {
		logs_info[v] = filepath.Join(logDir, v+".log")
	}
	return logger.NewLogs(logs_info)
}

func buildHttpServer(n *node.Node) (*http.Server, error) {
	gin.SetMode(gin.ReleaseMode)
	ginsrv := gin.Default()
	ginConfig := cors.DefaultConfig()
	ginConfig.AllowAllOrigins = true
	ginConfig.AddAllowHeaders("*")
	ginsrv.Use(cors.New(ginConfig))

	// route
	ginsrv.POST("/feedback/log", n.FeedbackLog)
	ginsrv.POST("/restore", n.RestoreFile)

	ginsrv.GET(fmt.Sprintf("/:%s", node.HTTP_ParameterName), n.GetHandle)
	ginsrv.GET("/restore", n.GetRestoreHandle)
	ginsrv.GET("/version", n.Get_version)
	ginsrv.GET("/bucket", n.Get_bucket)
	ginsrv.GET(fmt.Sprintf("/metedata/:%s", node.HTTP_ParameterName_Fid), n.Get_metadata)
	ginsrv.GET(fmt.Sprintf("/download/:%s", node.HTTP_ParameterName_Fid), n.Download_file)
	ginsrv.GET(fmt.Sprintf("/canfiles/:%s", node.HTTP_ParameterName_Fid), n.GetCanFileHandle)
	ginsrv.GET(fmt.Sprintf("/open/:%s", node.HTTP_ParameterName_Fid), n.Preview_file)

	ginsrv.PUT("/bucket", n.Put_bucket)
	ginsrv.PUT("/file", n.Put_file)
	ginsrv.PUT("/object", n.Put_object)
	ginsrv.PUT("/chunks", n.PutChunksHandle)

	ginsrv.DELETE(fmt.Sprintf("/file/:%s", node.HTTP_ParameterName), n.DelHandle)
	ginsrv.DELETE(fmt.Sprintf("/bucket/:%s", node.HTTP_ParameterName), n.DelHandle)
	ginsrv.DELETE("/", n.DelHandle)

	ginsrv.GET("/404", n.NotFoundHandler)

	// http server
	return &http.Server{
		Addr:           fmt.Sprintf(":%d", n.GetHttpPort()),
		Handler:        ginsrv,
		ReadTimeout:    time.Duration(30) * time.Second,
		WriteTimeout:   time.Duration(30) * time.Second,
		MaxHeaderBytes: 1024 * 1024,
	}, nil
}
