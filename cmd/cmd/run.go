/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/DeOSS/pkg/utils"
	cess "github.com/CESSProject/cess-go-sdk"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	p2pgo "github.com/CESSProject/p2p-go"
	"github.com/CESSProject/p2p-go/config"
	"github.com/CESSProject/p2p-go/core"
	"github.com/CESSProject/p2p-go/out"
	"github.com/howeyc/gopass"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// cmd_run_func is an implementation of the run command,
// which is used to start the deoss service.
func cmd_run_func(cmd *cobra.Command, args []string) {
	var (
		registerFlag   bool
		err            error
		logDir         string
		dbDir          string
		trackDir       string
		fadebackDir    string
		ufileDir       string
		dfileDir       string
		protocolPrefix string
		bootEnv        string
		syncSt         pattern.SysSyncState
		n              = node.New()
	)
	ctx := context.Background()
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

	boots := n.GetBootNodes()
	for _, v := range boots {
		if strings.Contains(v, "testnet") {
			bootEnv = "cess-testnet"
			protocolPrefix = config.TestnetProtocolPrefix
			break
		} else if strings.Contains(v, "mainnet") {
			bootEnv = "cess-mainnet"
			protocolPrefix = config.MainnetProtocolPrefix
			break
		} else if strings.Contains(v, "devnet") {
			bootEnv = "cess-devnet"
			protocolPrefix = config.DevnetProtocolPrefix
			break
		} else {
			bootEnv = "unknown"
		}
	}

	// Build sdk
	n.SDK, err = cess.New(
		ctx,
		cess.Name(sconfig.CharacterName_Deoss),
		cess.ConnectRpcAddrs(n.GetRpcAddr()),
		cess.Mnemonic(n.GetMnemonic()),
		cess.TransactionTimeout(configs.TimeOut_WaitBlock),
	)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}
	defer n.GetSubstrateAPI().Client.Close()

	n.PeerNode, err = p2pgo.New(
		ctx,
		p2pgo.ListenPort(n.GetP2pPort()),
		p2pgo.Workspace(filepath.Join(n.GetWorkspace(), n.GetSignatureAcc(), n.GetSDKName())),
		p2pgo.BootPeers(n.GetBootNodes()),
		p2pgo.ProtocolPrefix(protocolPrefix),
	)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}

	out.Tip(fmt.Sprintf("chain network: %s", n.GetNetworkEnv()))
	out.Tip(fmt.Sprintf("p2p network: %s", bootEnv))
	if strings.Contains(bootEnv, "test") {
		if !strings.Contains(n.GetNetworkEnv(), "test") {
			out.Warn("chain and p2p are not in the same network")
		}
	}

	if strings.Contains(bootEnv, "main") {
		if !strings.Contains(n.GetNetworkEnv(), "main") {
			out.Warn("chain and p2p are not in the same network")
		}
	}

	if strings.Contains(bootEnv, "dev") {
		if !strings.Contains(n.GetNetworkEnv(), "dev") {
			out.Warn("chain and p2p are not in the same network")
		}
	}

	for {
		syncSt, err = n.SyncState()
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

	ossinfo, err := n.QueryDeOSSInfo(n.GetSignatureAccPulickey())
	if err != nil {
		if err.Error() == pattern.ERR_Empty {
			registerFlag = true
		} else {
			out.Err("Weak network signal or rpc service failure")
			os.Exit(1)
		}
	}

	if registerFlag {
		_, err = n.RegisterDeOSS(n.GetPeerPublickey(), n.GetDomainName())
		if err != nil {
			out.Err(fmt.Sprintf("register deoss err: %v", err))
			os.Exit(1)
		}
		n.RebuildDirs()
	} else {
		newPeerid := n.GetPeerPublickey()
		if !sutils.CompareSlice([]byte(string(ossinfo.Peerid[:])), newPeerid) ||
			n.GetDomainName() != string(ossinfo.Domain) {
			txhash, err := n.UpdateDeOSS(string(newPeerid), n.GetDomainName())
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
	if cacheDir == "" {
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

	out.Tip(n.Workspace())

	// run
	n.Run()
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
