/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package confile

import (
	"os"
	"path"
	"strconv"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	ProfileDefault  = "conf.toml"
	ProfileTemplete = `# The rpc address of the chain node
RpcAddr     = ""
# The IP address of the machine's public network used by the scheduler program
ServiceAddr = ""
# Port number monitored by the scheduler program
ServicePort = ""
# Data storage directory
DataDir     = ""
# Phrase or seed of wallet account
AccountSeed = ""`
)

type Confiler interface {
	Parse(path string) error
	GetRpcAddr() string
	GetServiceAddr() string
	GetServicePort() string
	GetDataDir() string
	GetCtrlPrk() string
}

type confile struct {
	RpcAddr     string `name:"RpcAddr" toml:"RpcAddr" yaml:"RpcAddr"`
	ServiceAddr string `name:"ServiceAddr" toml:"ServiceAddr" yaml:"ServiceAddr"`
	ServicePort string `name:"ServicePort" toml:"ServicePort" yaml:"ServicePort"`
	DataDir     string `name:"DataDir" toml:"DataDir" yaml:"DataDir"`
	AccountSeed string `name:"AccountSeed" toml:"AccountSeed" yaml:"AccountSeed"`
}

func NewConfigfile() Confiler {
	return &confile{}
}

func (c *confile) Parse(fpath string) error {
	var confilePath = fpath
	if confilePath == "" {
		confilePath = ProfileDefault
	}
	fstat, err := os.Stat(confilePath)
	if err != nil {
		return errors.Errorf("Parse: %v", err)
	}
	if fstat.IsDir() {
		return errors.Errorf("The '%v' is not a file", confilePath)
	}

	viper.SetConfigFile(confilePath)
	viper.SetConfigType(path.Ext(confilePath)[1:])

	err = viper.ReadInConfig()
	if err != nil {
		return errors.Errorf("ReadInConfig: %v", err)
	}
	err = viper.Unmarshal(c)
	if err != nil {
		return errors.Errorf("Unmarshal: %v", err)
	}

	_, err = signature.KeyringPairFromSecret(c.AccountSeed, 0)
	if err != nil {
		return errors.Errorf("Secret: %v", err)
	}

	if c.RpcAddr == "" ||
		c.ServiceAddr == "" {
		return errors.New("The configuration file cannot have empty entries")
	}

	port, err := strconv.Atoi(c.ServicePort)
	if err != nil {
		return errors.New("The port number should be between 1025~65535")
	}
	if port < 1024 {
		return errors.Errorf("Prohibit the use of system reserved port: %v", port)
	}
	if port > 65535 {
		return errors.New("The port number cannot exceed 65535")
	}

	fstat, err = os.Stat(c.DataDir)
	if err != nil {
		err = os.MkdirAll(c.DataDir, configs.DirPermission)
		if err != nil {
			return err
		}
	}

	if !fstat.IsDir() {
		return errors.Errorf("The '%v' is not a directory", c.DataDir)
	}

	return nil
}

func (c *confile) GetRpcAddr() string {
	return c.RpcAddr
}

func (c *confile) GetServiceAddr() string {
	return c.ServiceAddr
}

func (c *confile) GetServicePort() string {
	return c.ServicePort
}

func (c *confile) GetDataDir() string {
	return c.DataDir
}

func (c *confile) GetCtrlPrk() string {
	return c.AccountSeed
}
