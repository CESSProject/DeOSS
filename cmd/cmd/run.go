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
	sdkgo "github.com/CESSProject/cess-go-sdk"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/core/utils"
	"github.com/CESSProject/p2p-go/config"
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
		protocolPrefix string
		syncSt         pattern.SysSyncState
		n              = node.New()
	)

	// Building Profile Instances
	n.Confile, err = buildConfigFile(cmd)
	if err != nil {
		out.Err(err.Error())
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
			out.Tip("Test network")
			protocolPrefix = config.TestnetProtocolPrefix
			break
		} else if strings.Contains(v, "mainnet") {
			out.Tip("Main network")
			protocolPrefix = config.MainnetProtocolPrefix
			break
		} else if strings.Contains(v, "devnet") {
			out.Tip("Dev network")
			protocolPrefix = config.DevnetProtocolPrefix
			break
		} else {
			out.Tip("Unknown network")
		}
	}

	// Build sdk
	n.SDK, err = sdkgo.New(
		context.Background(),
		sconfig.CharacterName_Deoss,
		sdkgo.ConnectRpcAddrs(n.GetRpcAddr()),
		sdkgo.Mnemonic(n.GetMnemonic()),
		sdkgo.TransactionTimeout(configs.TimeOut_WaitBlock),
		sdkgo.Workspace(n.GetWorkspace()),
		sdkgo.P2pPort(n.GetP2pPort()),
		sdkgo.Bootnodes(n.GetBootNodes()),
		sdkgo.ProtocolPrefix(protocolPrefix),
	)
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
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

	_, err = n.QueryDeossPeerPublickey(n.GetSignatureAccPulickey())
	if err != nil {
		if err.Error() == pattern.ERR_Empty {
			registerFlag = true
		} else {
			out.Err("Weak network signal or rpc service failure")
			os.Exit(1)
		}
	}

	_, _, err = n.Register(n.GetRoleName(), n.GetPeerPublickey(), "", 0)
	if err != nil {
		out.Err(fmt.Sprintf("Register or update err: %v", err))
		os.Exit(1)
	}

	if registerFlag {
		n.RebuildDirs()
	}

	logDir, dbDir, n.TrackDir, err = buildDir(n.Workspace())
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}

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

	out.Tip(n.GetProtocolPrefix())

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

func buildDir(workspace string) (string, string, string, error) {
	logDir := filepath.Join(workspace, configs.Log)
	if err := os.MkdirAll(logDir, pattern.DirMode); err != nil {
		return "", "", "", err
	}

	cacheDir := filepath.Join(workspace, configs.Db)
	if err := os.MkdirAll(cacheDir, pattern.DirMode); err != nil {
		return "", "", "", err
	}

	trackDir := filepath.Join(workspace, configs.Track)
	if err := os.MkdirAll(trackDir, pattern.DirMode); err != nil {
		return "", "", "", err
	}

	return logDir, cacheDir, trackDir, nil
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
