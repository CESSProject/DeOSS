/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/CESSProject/DeOSS/common/logger"
	"github.com/CESSProject/DeOSS/common/utils"
	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	cess "github.com/CESSProject/cess-go-sdk"
	"github.com/CESSProject/cess-go-sdk/chain"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	p2pgo "github.com/CESSProject/p2p-go"
	"github.com/CESSProject/p2p-go/out"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// cmd_run_func is an implementation of the run command,
// which is used to start the deoss service.
func cmd_run_func(cmd *cobra.Command, args []string) {
	var (
		err error
	)

	ctx := cmd.Context()
	n := node.New()

	n.Config, err = readEnv()
	if err != nil {
		n.Config, err = buildConfigFile(cmd)
		if err != nil {
			out.Err("buildConfigFile: " + err.Error())
			os.Exit(1)
		}
	}

	err = n.Setup()
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}

	n.ChainClient, err = cess.New(
		ctx,
		cess.Name(configs.Name),
		cess.ConnectRpcAddrs(n.Config.Chain.Rpc),
		cess.Mnemonic(n.Config.Chain.Mnemonic),
		cess.TransactionTimeout(time.Second*time.Duration(n.Config.Chain.Timeout)),
	)
	if err != nil {
		out.Err(fmt.Sprintf("[cess.New] %v", err))
		os.Exit(1)
	}
	defer n.ChainClient.Close()

	err = n.InitExtrinsicsNameForOSS()
	if err != nil {
		log.Println("The rpc address does not match the software version, please check the rpc address.")
		os.Exit(1)
	}

	var syncSt chain.SysSyncState
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

	registerFlag := false
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
		p2pgo.Workspace(n.GetBasespace()),
		p2pgo.ListenPort(int(n.Config.Storage.Port)),
		p2pgo.BootPeers(n.Config.Storage.Boot),
	)
	if err != nil {
		out.Err(fmt.Sprintf("[p2pgo.New] %v", err))
		os.Exit(1)
	}
	defer n.PeerNode.Close()

	n.LoadPeer(filepath.Join(n.GetBasespace(), "peer_record"))

	go node.Subscribe(
		ctx, n.PeerNode.GetHost(),
		n.PeerNode.GetBootnode(),
		func(p peer.AddrInfo) { n.SavePeer(p) },
	)
	time.Sleep(time.Second)

	out.Tip(fmt.Sprintf("chain network: %s", n.GetNetworkEnv()))

	if registerFlag {
		_, err = n.RegisterOss(n.GetPeerPublickey(), n.Config.Application.Url)
		if err != nil {
			out.Err(fmt.Sprintf("register deoss err: %v", err))
			os.Exit(1)
		}
		n.RebuildDirs()
	} else {
		newPeerid := n.GetPeerPublickey()
		if !sutils.CompareSlice([]byte(string(ossinfo.Peerid[:])), newPeerid) ||
			n.Config.Application.Url != string(ossinfo.Domain) {
			txhash, err := n.UpdateOss(string(newPeerid), n.Config.Application.Url)
			if err != nil {
				out.Err(fmt.Sprintf("[%s] update deoss err: %v", txhash, err))
				os.Exit(1)
			}
		}
	}

	// init extension components
	cacheDir := n.Config.Cacher.Directory
	if cacheDir == "" {
		cacheDir = filepath.Join(n.GetBasespace(), configs.FILE_CACHE)
	}
	n.InitFileCache(
		time.Duration(n.Config.Cacher.Expiration),
		int64(n.Config.Cacher.Size),
		cacheDir,
	)
	nodeFilePath := n.Config.Selector.Filter
	if nodeFilePath == "" {
		nodeFilePath = filepath.Join(n.GetBasespace(), "storage_nodes.json")
	}
	n.InitNodeSelector(
		n.Config.Selector.Strategy,
		nodeFilePath,
		int(n.Config.Selector.Number),
		int64(n.Config.Selector.Ttl),
		int64(n.Config.Selector.Refresh),
	)

	n.Logger, err = buildLogs(n.GetLogDir())
	if err != nil {
		out.Err(err.Error())
		os.Exit(1)
	}

	out.Tip(n.GetBasespace())

	n.Run()
}

func readEnv() (*confile.Config, error) {
	var c = &confile.Config{}

	// workspace
	c.Workspace = os.Getenv("workspace")
	err := os.MkdirAll(c.Workspace, 0755)
	if err != nil {
		return nil, errors.Errorf("create workspace: %v", err)
	}

	// url
	c.Url = os.Getenv("url")

	// mode
	c.Application.Mode = os.Getenv("mode")
	if c.Application.Mode != configs.App_Mode_Release && c.Application.Mode != configs.App_Mode_Debug {
		if c.Application.Mode == "" {
			c.Application.Mode = configs.App_Mode_Release
		} else {
			return nil, errors.New("invalid application mode: " + c.Application.Mode)
		}
	}

	// port
	port, err := strconv.Atoi(os.Getenv("port"))
	if err != nil {
		return nil, errors.Errorf("invalid application port: %v", err)
	}
	if !confile.FreeLocalPort(uint32(port)) {
		return nil, errors.Errorf("the port %d is in use", port)
	}
	c.Application.Port = uint32(port)

	// mnemonic
	c.Mnemonic = os.Getenv("mnemonic")
	_, err = signature.KeyringPairFromSecret(c.Mnemonic, 0)
	if err != nil {
		return nil, errors.Errorf("invalid mnemonic in env: %v", err)
	}

	// timeout
	timeout, err := strconv.Atoi(os.Getenv("timeout"))
	if err != nil {
		c.Timeout = configs.DefaultTxTimeOut
	} else {
		c.Timeout = timeout
	}

	// rpc
	rpcs := strings.Split(os.Getenv("rpc"), " ")
	if len(rpcs) <= 0 {
		c.Rpc = []string{configs.DefaultRpcAddress}
	} else {
		c.Rpc = rpcs
	}

	// storage network port
	sport, err := strconv.Atoi(os.Getenv("storage_port"))
	if err != nil {
		return nil, errors.Errorf("invalid storage network port: %v", err)
	}
	if !confile.FreeLocalPort(uint32(sport)) {
		return nil, errors.Errorf("the port %d is in use", port)
	}
	c.Storage.Port = uint32(sport)

	// boot
	boots := strings.Split(os.Getenv("boot"), " ")
	if len(boots) <= 0 {
		c.Storage.Boot = []string{configs.DefaultRpcAddress}
	} else {
		c.Storage.Boot = boots
	}

	// high priority account
	accounts := strings.Split(os.Getenv("account"), " ")
	c.User.Account = accounts

	// black/white mode
	c.Access.Mode = os.Getenv("bwmode")
	if c.Access.Mode != configs.Access_Public && c.Access.Mode != configs.Access_Private {
		if c.Access.Mode == "" {
			c.Access.Mode = configs.Access_Public
		} else {
			return nil, errors.New("invalid access mode")
		}
	}

	// black/white account
	bwaccounts := strings.Split(os.Getenv("bwaccount"), " ")
	c.User.Account = bwaccounts

	// cache size
	size, _ := strconv.Atoi(os.Getenv("size"))
	c.Cacher.Size = uint64(size)

	// cache expiration
	expiration, _ := strconv.Atoi(os.Getenv("expiration"))
	c.Cacher.Expiration = uint32(expiration)

	// cache directory
	c.Cacher.Directory = os.Getenv("directory")

	// selector strategy
	c.Selector.Strategy = os.Getenv("strategy")

	// selector filter
	c.Selector.Filter = os.Getenv("filter")

	// selector number
	number, _ := strconv.Atoi(os.Getenv("number"))
	c.Selector.Number = uint64(number)

	// selector TTL
	ttl, _ := strconv.Atoi(os.Getenv("ttl"))
	c.Selector.Ttl = uint64(ttl)

	// selector refresh
	refresh, _ := strconv.Atoi(os.Getenv("refresh"))
	c.Selector.Refresh = uint32(refresh)

	// high priority peerid
	peerids := strings.Split(os.Getenv("peerid"), " ")
	c.Peerid = peerids
	return c, nil
}

func buildConfigFile(cmd *cobra.Command) (*confile.Config, error) {
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
	}

	return confile.NewConfig(conFilePath)
}

func buildLogs(logDir string) (logger.Logger, error) {
	var logs_info = make(map[string]string)
	for _, v := range logger.LogFiles {
		logs_info[v] = filepath.Join(logDir, v+".log")
	}
	return logger.NewLogs(logs_info)
}
