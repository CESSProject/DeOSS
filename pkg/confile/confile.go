/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package confile

import (
	"fmt"
	"os"
	"path"

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
	Parse(fpath string, ip string, port int) error
	GetRpcAddr() []string
	GetServiceAddr() string
	GetServicePort() int
	GetWorkspace() string
	GetMnemonic() string
	GetPublickey() ([]byte, error)
}

type confile struct {
	Rpc       []string `name:"Rpc" toml:"Rpc" yaml:"Rpc"`
	Mnemonic  string   `name:"Mnemonic" toml:"Mnemonic" yaml:"Mnemonic"`
	Workspace string   `name:"Workspace" toml:"Workspace" yaml:"Workspace"`
	Address   string   `name:"Address" toml:"Address" yaml:"Address"`
	Port      int      `name:"Port" toml:"Port" yaml:"Port"`
}

func NewConfigfile() *confile {
	return &confile{}
}

func (c *confile) Parse(fpath string, ip string, port int) error {
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

	_, err = signature.KeyringPairFromSecret(c.Mnemonic, 0)
	if err != nil {
		return errors.Errorf("Secret: %v", err)
	}

	if ip != "" {
		c.Address = ip
	}
	if len(c.Rpc) == 0 ||
		c.Address == "" {
		return errors.New("The configuration file cannot have empty entries")
	}

	if port != 0 {
		c.Port = port
	}
	if c.Port < 1024 {
		return errors.Errorf("Prohibit the use of system reserved port: %v", c.Port)
	}
	if c.Port > 65535 {
		return errors.New("The port number cannot exceed 65535")
	}

	fstat, err = os.Stat(c.Workspace)
	if err != nil {
		err = os.MkdirAll(c.Workspace, configs.DirPermission)
		if err != nil {
			return err
		}
	}

	if !fstat.IsDir() {
		return errors.Errorf("The '%v' is not a directory", c.Workspace)
	}

	return nil
}

func (c *confile) SetRpcAddr(rpc []string) {
	c.Rpc = rpc
}

func (c *confile) SetServiceAddr(address string) error {
	c.Address = address
	return nil
}

func (c *confile) SetServicePort(port int) error {
	if c.Port < 1024 {
		return errors.Errorf("Prohibit the use of system reserved port: %v", c.Port)
	}
	if c.Port > 65535 {
		return errors.New("The port number cannot exceed 65535")
	}
	c.Port = port
	return nil
}

func (c *confile) SetWorkspace(workspace string) error {
	fstat, err := os.Stat(workspace)
	if err != nil {
		err = os.MkdirAll(workspace, configs.DirPermission)
		if err != nil {
			return err
		}
	}
	if !fstat.IsDir() {
		return fmt.Errorf("%s is not a directory", workspace)
	}
	c.Workspace = workspace
	return nil
}

func (c *confile) SetMnemonic(mnemonic string) error {
	_, err := signature.KeyringPairFromSecret(mnemonic, 0)
	if err != nil {
		return err
	}
	c.Mnemonic = mnemonic
	return nil
}

func (c *confile) GetRpcAddr() []string {
	return c.Rpc
}

func (c *confile) GetServiceAddr() string {
	return c.Address
}

func (c *confile) GetServicePort() int {
	return c.Port
}

func (c *confile) GetWorkspace() string {
	return c.Workspace
}

func (c *confile) GetMnemonic() string {
	return c.Mnemonic
}

func (c *confile) GetPublickey() ([]byte, error) {
	key, err := signature.KeyringPairFromSecret(c.GetMnemonic(), 0)
	if err != nil {
		return nil, err
	}
	return key.PublicKey, nil
}
