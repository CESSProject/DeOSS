/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"os"
	"strconv"
	"strings"

	"github.com/CESSProject/DeOSS/common/confile"
	out "github.com/CESSProject/DeOSS/common/fout"
	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// cmd_run_func is an implementation of the run command,
// which is used to start the deoss service.
func runCmd(cmd *cobra.Command, args []string) {
	node.NewNodeWithConfig(InitConfig(cmd)).InitNode().Start()
}

func InitConfig(cmd *cobra.Command) *confile.Config {
	cfg, err := readEnv()
	if err != nil {
		cfg, err = buildConfigFile(cmd)
		if err != nil {
			out.Err("buildConfigFile: " + err.Error())
			os.Exit(1)
		}
	}
	return cfg
}

func readEnv() (*confile.Config, error) {
	var c = &confile.Config{}

	// workspace
	c.Workspace = os.Getenv("workspace")
	err := os.MkdirAll(c.Workspace, 0755)
	if err != nil {
		return nil, errors.Errorf("create workspace: %v", err)
	}

	// visibility
	c.Visibility = os.Getenv("visibility")
	if c.Application.Visibility != configs.Access_Public && c.Application.Visibility != configs.Access_Private {
		if c.Application.Visibility == "" {
			c.Application.Visibility = configs.Access_Public
		} else {
			return nil, errors.New("invalid visibility: " + c.Application.Visibility)
		}
	}

	// domainname
	c.Domainname = os.Getenv("domainname")

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

	// maxusespace
	maxusespace, err := strconv.ParseUint(os.Getenv("maxusespace"), 10, 64)
	if err != nil {
		return nil, errors.Errorf("invalid maxusespace: %v", maxusespace)
	}
	c.Application.Maxusespace = maxusespace

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

	// specify storage miner account
	c.Shunt.Account = strings.Split(os.Getenv("specify_miner"), " ")
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
