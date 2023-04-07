/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"log"
	"os"
	"path/filepath"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/DeOSS/pkg/utils"
	sdkgo "github.com/CESSProject/sdk-go"
	"github.com/spf13/cobra"
)

// Start service
func Command_Run_Runfunc(cmd *cobra.Command, args []string) {
	var (
		err    error
		logDir string
		dbDir  string
		n      = node.New()
	)

	// Building Profile Instances
	n.Confile, err = buildConfigFile(cmd, "", 0)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	//Build client
	n.Cli, err = sdkgo.New(
		configs.Name,
		sdkgo.ConnectRpcAddrs(n.Confile.GetRpcAddr()),
		sdkgo.ListenPort(n.Confile.GetServicePort()),
		sdkgo.Workspace(n.Confile.GetWorkspace()),
		sdkgo.Mnemonic(n.Confile.GetMnemonic()),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	_, err = n.Cli.Register(configs.Name, "", 0)
	if err != nil {
		log.Println("Register err: ", err)
		os.Exit(1)
	}

	logDir, dbDir, n.FileDir, n.TrackDir, err = buildDir(n.Cli.Workspace())
	if err != nil {
		log.Println("buildDir err: ", err)
		os.Exit(1)
	}

	//Build cache
	n.Cache, err = buildCache(dbDir)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	//Build Log
	n.Logs, err = buildLogs(logDir)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// run
	n.Run()
}

func buildConfigFile(cmd *cobra.Command, ip4 string, port int) (confile.Confiler, error) {
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
	err := cfg.Parse(conFilePath, ip4, port)
	if err == nil {
		return cfg, err
	}

	rpc, err := cmd.Flags().GetString("rpc")
	if err != nil {
		return cfg, err
	}
	workspace, err := cmd.Flags().GetString("ws")
	if err != nil {
		return cfg, err
	}
	ip, err := cmd.Flags().GetString("ip")
	if err != nil {
		return cfg, err
	}
	port, err = cmd.Flags().GetInt("port")
	if err != nil {
		port, err = cmd.Flags().GetInt("p")
		if err != nil {
			return cfg, err
		}
	}
	cfg.SetRpcAddr([]string{rpc})
	err = cfg.SetWorkspace(workspace)
	if err != nil {
		return cfg, err
	}
	err = cfg.SetServiceAddr(ip)
	if err != nil {
		return cfg, err
	}
	err = cfg.SetServicePort(port)
	if err != nil {
		return cfg, err
	}
	mnemonic, err := utils.PasswdWithMask("Please enter your mnemonic and press Enter to end:", "", "")
	if err != nil {
		return cfg, err
	}
	err = cfg.SetMnemonic(mnemonic)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

func buildDir(workspace string) (string, string, string, string, error) {
	logDir := filepath.Join(workspace, configs.Log)
	if err := os.MkdirAll(logDir, configs.DirPermission); err != nil {
		return "", "", "", "", err
	}

	cacheDir := filepath.Join(workspace, configs.Db)
	if err := os.MkdirAll(cacheDir, configs.DirPermission); err != nil {
		return "", "", "", "", err
	}

	fileDir := filepath.Join(workspace, configs.File)
	if err := os.MkdirAll(fileDir, configs.DirPermission); err != nil {
		return "", "", "", "", err
	}

	trackDir := filepath.Join(workspace, configs.Track)
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
