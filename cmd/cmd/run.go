/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	"github.com/CESSProject/DeOSS/pkg/chain"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/spf13/cobra"
)

// start service
func Command_Run_Runfunc(cmd *cobra.Command, args []string) {
	var (
		err      error
		logDir   string
		cacheDir string
		node     = node.New()
	)

	// Building Profile Instances
	node.Confile, err = buildConfigFile(cmd)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	//Build chain instance
	node.Chain, err = buildChain(node.Confile, configs.TimeOut_WaitBlock)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	go node.Chain.KeepConnect()

	//Build Data Directory
	logDir, cacheDir, node.FileDir, node.TrackDir, err = buildDir(node.Confile, node.Chain)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	//Build cache instance
	node.Cache, err = buildCache(cacheDir)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	//Build Log Instance
	node.Logs, err = buildLogs(logDir)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// run
	node.Run()
}

func buildConfigFile(cmd *cobra.Command) (confile.Confiler, error) {
	var conFilePath string
	configpath1, _ := cmd.Flags().GetString("config")
	configpath2, _ := cmd.Flags().GetString("c")
	if configpath1 != "" {
		conFilePath = configpath1
	} else {
		conFilePath = configpath2
	}

	cfg := confile.NewConfigfile()
	if err := cfg.Parse(conFilePath); err != nil {
		return nil, err
	}
	return cfg, nil
}

func buildChain(cfg confile.Confiler, timeout time.Duration) (chain.Chainer, error) {
	// connecting chain
	client, err := chain.NewChainClient(cfg.GetRpcAddr(), cfg.GetCtrlPrk(), timeout)
	if err != nil {
		return nil, err
	}

	// judge the balance
	accountinfo, err := client.GetAccountInfo(client.GetPublicKey())
	if err != nil {
		return nil, err
	}

	if accountinfo.Data.Free.CmpAbs(new(big.Int).SetUint64(configs.MinimumBalance)) == -1 {
		return nil, fmt.Errorf("Account balance is less than %v pico\n", configs.MinimumBalance)
	}

	// sync block
	for {
		ok, err := client.GetSyncStatus()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		log.Println("In sync block...")
		time.Sleep(time.Second * configs.BlockInterval)
	}
	log.Println("Complete synchronization of primary network block data")

	// whether to register
	ossStata, err := client.GetState(client.GetPublicKey())
	if err != nil && err.Error() != chain.ERR_RPC_EMPTY_VALUE.Error() {
		return nil, err
	}

	// register
	if ossStata == "" {
		if err := register(cfg, client); err != nil {
			return nil, err
		}
	}
	return client, nil
}

func register(cfg confile.Confiler, client chain.Chainer) error {
	txhash, err := client.Register(cfg.GetServiceAddr(), cfg.GetServicePort())
	if err != nil {
		if err.Error() == chain.ERR_RPC_EMPTY_VALUE.Error() {
			return fmt.Errorf("[err] Please check your wallet balance")
		} else {
			if txhash != "" {
				msg := configs.HELP_common + fmt.Sprintf(" %v\n", txhash)
				msg += configs.HELP_register
				return fmt.Errorf("[pending] %v\n", msg)
			}
			return err
		}
	}
	ctlAccount, _ := client.GetCessAccount()
	baseDir := filepath.Join(cfg.GetDataDir(), ctlAccount, configs.BaseDir)
	os.RemoveAll(baseDir)
	return nil
}

func buildDir(cfg confile.Confiler, client chain.Chainer) (string, string, string, string, error) {
	ctlAccount, err := client.GetCessAccount()
	if err != nil {
		return "", "", "", "", err
	}
	baseDir := filepath.Join(cfg.GetDataDir(), ctlAccount, configs.BaseDir)

	_, err = os.Stat(baseDir)
	if err != nil {
		err = os.MkdirAll(baseDir, configs.DirPermission)
		if err != nil {
			return "", "", "", "", err
		}
	}

	logDir := filepath.Join(baseDir, configs.Log)
	if err := os.MkdirAll(logDir, configs.DirPermission); err != nil {
		return "", "", "", "", err
	}

	cacheDir := filepath.Join(baseDir, configs.Cache)
	if err := os.MkdirAll(cacheDir, configs.DirPermission); err != nil {
		return "", "", "", "", err
	}

	fileDir := filepath.Join(baseDir, configs.File)
	if err := os.MkdirAll(fileDir, configs.DirPermission); err != nil {
		return "", "", "", "", err
	}

	trackDir := filepath.Join(baseDir, configs.Track)
	if err := os.MkdirAll(trackDir, configs.DirPermission); err != nil {
		return "", "", "", "", err
	}

	return logDir, cacheDir, fileDir, trackDir, nil
}

func buildCache(cacheDir string) (db.Cacher, error) {
	cache, err := db.NewCache(cacheDir, 0, 0, configs.NameSpace)
	if err != nil {
		return nil, err
	}

	ok, err := cache.Has([]byte("SigningKey"))
	if err != nil {
		return nil, err
	}
	if !ok {
		err = cache.Put([]byte("SigningKey"), []byte(utils.GetRandomcode(16)))
	}
	return cache, err
}

func buildLogs(logDir string) (logger.Logger, error) {
	var logs_info = make(map[string]string)
	for _, v := range configs.LogFiles {
		logs_info[v] = filepath.Join(logDir, v+".log")
	}
	return logger.NewLogs(logs_info)
}
