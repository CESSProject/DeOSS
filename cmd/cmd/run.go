/*
Copyright 2022 CESS scheduler authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/node"
	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/CESSProject/cess-oss/pkg/confile"
	"github.com/CESSProject/cess-oss/pkg/db"
	"github.com/CESSProject/cess-oss/pkg/logger"
	"github.com/CESSProject/cess-oss/pkg/utils"
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

	//Build Data Directory
	logDir, cacheDir, node.FileDir, err = buildDir(node.Confile, node.Chain)
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
	return nil
}

func buildDir(cfg confile.Confiler, client chain.Chainer) (string, string, string, error) {
	ctlAccount, err := client.GetCessAccount()
	if err != nil {
		return "", "", "", err
	}
	baseDir := filepath.Join(cfg.GetDataDir(), ctlAccount, configs.BaseDir)

	_, err = os.Stat(baseDir)
	if err != nil {
		err = os.MkdirAll(baseDir, os.ModeDir)
		if err != nil {
			return "", "", "", err
		}
	}

	logDir := filepath.Join(baseDir, configs.Log)
	_, err = os.Stat(logDir)
	if err == nil {
		bkp := logDir + fmt.Sprintf("_%v", time.Now().Unix())
		os.Rename(logDir, bkp)
	}
	if err := os.MkdirAll(logDir, os.ModeDir); err != nil {
		return "", "", "", err
	}

	cacheDir := filepath.Join(baseDir, configs.Cache)
	os.RemoveAll(cacheDir)
	if err := os.MkdirAll(cacheDir, os.ModeDir); err != nil {
		return "", "", "", err
	}

	fileDir := filepath.Join(baseDir, configs.File)
	os.RemoveAll(fileDir)
	if err := os.MkdirAll(fileDir, os.ModeDir); err != nil {
		return "", "", "", err
	}

	log.Println(baseDir)
	return logDir, cacheDir, fileDir, nil
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
