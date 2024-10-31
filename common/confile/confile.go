/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package confile

import (
	"fmt"
	"net"
	"os"
	"path"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	DefaultConfig  = "conf.yaml"
	ConfigTemplete = `application:
  # gateway's workspace
  workspace: /
  # gateway run mode  [debug | release]
  mode: release
  # service visibility: [public | private]
  # public: gateway address will be published on the chain
  # private: gateway address will not be made public on the chain
  visibility: public
  # domain name, if it's empty and the visibility is public, the <ip:port> will be published on the chain
  domainname: 
  # maximum space occupied, gateway will automatically clean up the cached files
  maxusespace: 1099511627776
  # gateway API communication port, default is 8080
  port: 8080

chain:
  # signature account mnemonic
  mnemonic: ""
  # waiting for transaction timeout, default is 15 seconds
  timeout: 15
  # rpc endpoint list
  rpc:
    # test network
    - "wss://testnet-rpc.cess.network/ws/"

user:
  # high priority accounts will not be restricted or blacklisted when accessing the gateway
  account:

access:
  # access mode: [public | private]
  # public: only users in account can't access the gateway
  # private: only users in account can access the gateway
  mode: public
  # account black/white list
  account:

shunt:
  # specify the storage miner account you want to store
  account:`
)

type Application struct {
	Workspace   string `name:"workspace" toml:"workspace" yaml:"workspace"`
	Mode        string `name:"mode" toml:"mode" yaml:"mode"`
	Visibility  string `name:"visibility" toml:"visibility" yaml:"visibility"`
	Domainname  string `name:"domainname" toml:"domainname" yaml:"domainname"`
	Maxusespace uint64 `name:"maxusespace" toml:"maxusespace" yaml:"maxusespace"`
	Port        uint32 `name:"port" toml:"port" yaml:"port"`
}

type Chain struct {
	Mnemonic string   `name:"mnemonic" toml:"mnemonic" yaml:"mnemonic"`
	Timeout  int      `name:"timeout" toml:"timeout" yaml:"timeout"`
	Rpc      []string `name:"rpc" toml:"rpc" yaml:"rpc"`
}

type User struct {
	Account []string `name:"account" toml:"account" yaml:"account"`
}

type Access struct {
	Mode    string   `name:"mode" toml:"mode" yaml:"mode"`
	Account []string `name:"account" toml:"account" yaml:"account"`
}

type Shunt struct {
	Account []string `name:"account" toml:"account" yaml:"account"`
}

type Config struct {
	Application `yaml:"application"`
	Chain       `yaml:"chain"`
	User        `yaml:"user"`
	Access      `yaml:"access"`
	Shunt       `yaml:"shunt"`
}

func NewConfig(config_file string) (*Config, error) {
	var confilePath = config_file
	if confilePath == "" {
		confilePath = DefaultConfig
	}
	fstat, err := os.Stat(confilePath)
	if err != nil {
		return nil, err
	}
	if fstat.IsDir() {
		return nil, errors.Errorf("the '%v' is not a file", confilePath)
	}

	viper.SetConfigFile(confilePath)
	viper.SetConfigType(path.Ext(confilePath)[1:])

	err = viper.ReadInConfig()
	if err != nil {
		return nil, errors.Errorf("ReadInConfig: %v", err)
	}
	var c = &Config{}
	err = viper.Unmarshal(c)
	if err != nil {
		return nil, errors.Errorf("configuration file format error: %v", err)
	}

	if c.Mnemonic == "" {
		c.Mnemonic = os.Getenv("mnemonic")
	}

	_, err = signature.KeyringPairFromSecret(c.Mnemonic, 0)
	if err != nil {
		return nil, errors.Errorf("invalid mnemonic: %v", err)
	}

	if len(c.Rpc) == 0 {
		return nil, errors.New("empty rpc list")
	}

	if c.Application.Port > 65535 {
		return nil, errors.New("the port number cannot exceed 65535")
	}

	if !FreeLocalPort(c.Application.Port) {
		return nil, errors.Errorf("the port %d is in use", c.Application.Port)
	}

	if c.Application.Mode != configs.App_Mode_Release && c.Application.Mode != configs.App_Mode_Debug {
		return nil, errors.New("invalid application mode")
	}

	if c.Application.Visibility != configs.Access_Public && c.Application.Visibility != configs.Access_Private {
		return nil, errors.New("invalid visibility")
	}

	if c.Access.Mode != configs.Access_Public && c.Access.Mode != configs.Access_Private {
		return nil, errors.New("invalid access mode")
	}

	for i := 0; i < len(c.Shunt.Account); i++ {
		_, err = sutils.ParsingPublickey(c.Shunt.Account[i])
		if err != nil {
			return nil, errors.New("invalid shunt account")
		}
	}

	err = os.MkdirAll(c.Workspace, 0755)
	if err != nil {
		return nil, errors.Errorf("create workspace: %v", err)
	}

	return c, nil
}

func NewConfigNotCheck(config_file string) (*Config, error) {
	var confilePath = config_file
	if confilePath == "" {
		confilePath = DefaultConfig
	}
	fstat, err := os.Stat(confilePath)
	if err != nil {
		return nil, err
	}
	if fstat.IsDir() {
		return nil, errors.Errorf("the '%v' is not a file", confilePath)
	}

	viper.SetConfigFile(confilePath)
	viper.SetConfigType(path.Ext(confilePath)[1:])

	err = viper.ReadInConfig()
	if err != nil {
		return nil, errors.Errorf("ReadInConfig: %v", err)
	}
	var c = &Config{}
	err = viper.Unmarshal(c)
	if err != nil {
		return nil, errors.Errorf("configuration file format error: %v", err)
	}

	if c.Mnemonic == "" {
		c.Mnemonic = os.Getenv("mnemonic")
	}

	_, err = signature.KeyringPairFromSecret(c.Mnemonic, 0)
	if err != nil {
		return nil, errors.Errorf("invalid mnemonic: %v", err)
	}

	if len(c.Rpc) == 0 {
		return nil, errors.New("empty rpc list")
	}
	return c, nil
}

func (c *Config) IsHighPriorityAccount(acc string) bool {
	length := len(c.User.Account)
	for i := 0; i < length; i++ {
		if acc == c.User.Account[i] {
			return true
		}
	}
	return false
}

func FreeLocalPort(port uint32) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second*3)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}
