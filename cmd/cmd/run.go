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
	"os"
	"path/filepath"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/db"
	"github.com/CESSProject/DeOSS/pkg/logger"
	"github.com/CESSProject/DeOSS/pkg/utils"
	p2pgo "github.com/CESSProject/p2p-go"
	sdkgo "github.com/CESSProject/sdk-go"
	sconfig "github.com/CESSProject/sdk-go/config"
	"github.com/CESSProject/sdk-go/core/pattern"
	"github.com/howeyc/gopass"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/spf13/cobra"
)

// Start service
func Command_Run_Runfunc(cmd *cobra.Command, args []string) {
	var (
		err       error
		logDir    string
		dbDir     string
		bootstrap []string
		n         = node.New()
	)

	// Building Profile Instances
	n.Confile, err = buildConfigFile(cmd)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	//Build client
	n.SDK, err = sdkgo.New(
		sconfig.CharacterName_Deoss,
		sdkgo.ConnectRpcAddrs(n.GetRpcAddr()),
		sdkgo.Mnemonic(n.GetMnemonic()),
		sdkgo.TransactionTimeout(configs.TimeOut_WaitBlock),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	boot, _ := cmd.Flags().GetString("boot")
	if boot == "" {
		log.Printf("Empty boot node")
	} else {
		bootstrap, _ = utils.ParseMultiaddrs(boot)
		for _, v := range bootstrap {
			log.Printf(fmt.Sprintf("bootstrap node: %v", v))
			addr, err := ma.NewMultiaddr(v)
			if err != nil {
				continue
			}
			addrInfo, err := peer.AddrInfoFromP2pAddr(addr)
			if err != nil {
				continue
			}
			n.PutPeer(addrInfo.ID.Pretty(), addrInfo.Addrs)
		}
	}

	n.P2P, err = p2pgo.New(
		context.Background(),
		p2pgo.ListenPort(n.GetP2pPort()),
		p2pgo.Workspace(filepath.Join(n.GetWorkspace(), n.GetSignatureAcc(), configs.Name)),
		p2pgo.BootPeers(bootstrap),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	for {
		syncSt, err := n.SyncState()
		if err != nil {
			log.Println(err.Error())
			os.Exit(1)
		}
		if syncSt.CurrentBlock == syncSt.HighestBlock {
			log.Println(fmt.Sprintf("Synchronization main chain completed: %d", syncSt.CurrentBlock))
			break
		}
		log.Println(fmt.Sprintf("In the synchronization main chain: %d ...", syncSt.CurrentBlock))
		time.Sleep(time.Second * time.Duration(utils.Ternary(int64(syncSt.HighestBlock-syncSt.CurrentBlock)*6, 30)))
	}

	_, _, err = n.Register(configs.Name, n.GetPeerPublickey(), "", 0)
	if err != nil {
		log.Println("Register err: ", err)
		os.Exit(1)
	}

	logDir, dbDir, n.TrackDir, err = buildDir(n.P2P.Workspace())
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
	n.Logger, err = buildLogs(logDir)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	for _, v := range n.Addrs() {
		log.Println(fmt.Sprintf("Local multiaddr: %s/p2p/%s", v.String(), n.ID().Pretty()))
	}

	if n.GetDiscoverSt() {
		log.Println("Start node discovery service")
	}

	log.Println("p2p protocol version: " + n.GetProtocolVersion())
	log.Println("dht protocol version: " + n.GetDhtProtocolVersion())

	// run
	n.Run()
}

func buildConfigFile(cmd *cobra.Command) (confile.Confile, error) {
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
	boot, err := cmd.Flags().GetStringSlice("boot")
	if err != nil {
		return cfg, err
	}
	cfg.SetBootNodes(boot)
	workspace, err := cmd.Flags().GetString("ws")
	if err != nil {
		return cfg, err
	}
	http_port, err := cmd.Flags().GetInt("http_port")
	if err != nil {
		http_port, err = cmd.Flags().GetInt("hp")
		if err != nil {
			return cfg, err
		}
	}
	p2p_port, err := cmd.Flags().GetInt("p2p_port")
	if err != nil {
		p2p_port, err = cmd.Flags().GetInt("pp")
		if err != nil {
			return cfg, err
		}
	}
	cfg.SetRpcAddr(rpc)
	err = cfg.SetWorkspace(workspace)
	if err != nil {
		return cfg, err
	}
	err = cfg.SetHttpPort(http_port)
	if err != nil {
		return cfg, err
	}
	err = cfg.SetP2pPort(p2p_port)
	if err != nil {
		return cfg, err
	}
	log.Println("Please enter the mnemonic of the staking account:")
	for {
		pwd, err := gopass.GetPasswdMasked()
		if err != nil {
			if err.Error() == "interrupted" || err.Error() == "interrupt" || err.Error() == "killed" {
				os.Exit(0)
			}
			log.Println("Invalid mnemonic, please check and re-enter:")
			continue
		}
		if len(pwd) == 0 {
			log.Println("The mnemonic you entered is empty, please re-enter:")
			continue
		}
		err = cfg.SetMnemonic(string(pwd))
		if err != nil {
			log.Println("Invalid mnemonic, please check and re-enter:")
			continue
		}
		break
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

	log.Println("Please enter the mnemonic of the staking account:")
	for {
		pwd, err := gopass.GetPasswdMasked()
		if err != nil {
			if err.Error() == "interrupted" || err.Error() == "interrupt" || err.Error() == "killed" {
				os.Exit(0)
			}
			log.Println("Invalid mnemonic, please check and re-enter:")
			continue
		}
		if len(pwd) == 0 {
			log.Println("The mnemonic you entered is empty, please re-enter:")
			continue
		}
		err = cfg.SetMnemonic(string(pwd))
		if err != nil {
			log.Println("Invalid mnemonic, please check and re-enter:")
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
