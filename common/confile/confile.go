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
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	DefaultConfig  = "conf.yaml"
	ConfigTemplete = `application:
  # gateway's workspace
  workspace: ""
  # gateway's url
  url: ""
  # gateway run mode  [debug | release]
  mode: "release"
  # gateway API communication port
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

storage:
  # communication ports in the storage network
  port: 4001
  # bootstrap nodes in the storage network
  boot:
    # test network
    - "_dnsaddr.boot-miner-testnet.cess.network"

user:
  # high priority accounts will not be restricted or blacklisted when accessing the gateway
  account:

access:
  # access mode: [public | private]
  # In public mode, only users in account can't access it
  # In private mode, only users in account can access it
  mode: public
  # account black/white list
  account:

# user files cacher config
cacher:
  # file cache size, default 512G, (unit is byte)
  size: 549755813888
  # file cache expiration time, default 3 hour (unit is minutes)
  expiration: 180
  # directory to store file cache, default path: workspace/filecache/
  directory:

# storage mode selector config
selector:
  # used to find better storage node partners for gateway to upload or download files,
  # two strategies for using your specified storage nodes, [priority | fixed]
  strategy: priority
  # storage miner filter file, json format, if it does not exist, it will be automatically created.
  # you can configure which storage nodes to use or not use in this file.
  # default path: workspace/storage_nodes.json
  filter:
  # maximum number of storage nodes allowed for long-term cooperation, default 120
  number: 120
  # maximum tolerable TTL for communication with storage nodes, default 500 ms (unit is milliseconds)
  ttl: 500000000
  # available storage node list refresh time, default 4 hours (unit is hours)
  refresh: 4

shunt:
  # give priority to storing files to miners with these peerids
  peerid:`
)

type Application struct {
	Workspace string `name:"workspace" toml:"workspace" yaml:"workspace"`
	Url       string `name:"url" toml:"url" yaml:"url"`
	Mode      string `name:"mode" toml:"mode" yaml:"mode"`
	Port      uint32 `name:"port" toml:"port" yaml:"port"`
}

type Chain struct {
	Mnemonic string   `name:"mnemonic" toml:"mnemonic" yaml:"mnemonic"`
	Timeout  int      `name:"timeout" toml:"timeout" yaml:"timeout"`
	Rpc      []string `name:"rpc" toml:"rpc" yaml:"rpc"`
}

type Storage struct {
	Port uint32   `name:"port" toml:"port" yaml:"port"`
	Boot []string `name:"boot" toml:"boot" yaml:"boot"`
}

type User struct {
	Account []string `name:"account" toml:"account" yaml:"account"`
}

type Access struct {
	Mode    string   `name:"mode" toml:"mode" yaml:"mode"`
	Account []string `name:"account" toml:"account" yaml:"account"`
}

type Cacher struct {
	Size       uint64 `name:"size" toml:"size" yaml:"size"`
	Expiration uint32 `name:"expiration" toml:"expiration" yaml:"expiration"`
	Directory  string `name:"directory" toml:"directory" yaml:"directory"`
}

type Selector struct {
	Strategy string `name:"strategy" toml:"strategy" yaml:"strategy"`
	Filter   string `name:"filter" toml:"filter" yaml:"filter"`
	Number   uint64 `name:"number" toml:"number" yaml:"number"`
	Ttl      uint64 `name:"ttl" toml:"ttl" yaml:"ttl"`
	Refresh  uint32 `name:"refresh" toml:"refresh" yaml:"refresh"`
}

type Shunt struct {
	Peerid []string `name:"peerid" toml:"peerid" yaml:"peerid"`
}

type Config struct {
	Application `yaml:"application"`
	Chain       `yaml:"chain"`
	Storage     `yaml:"storage"`
	User        `yaml:"user"`
	Access      `yaml:"access"`
	Cacher      `yaml:"cacher"`
	Selector    `yaml:"selector"`
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

	_, err = signature.KeyringPairFromSecret(c.Mnemonic, 0)
	if err != nil {
		return nil, errors.Errorf("invalid mnemonic: %v", err)
	}

	if len(c.Rpc) == 0 || len(c.Boot) == 0 {
		return nil, errors.New("configuration file cannot have empty entries")
	}

	if c.Application.Port > 65535 || c.Storage.Port > 65535 {
		return nil, errors.New("the port number cannot exceed 65535")
	}

	if !FreeLocalPort(c.Application.Port) {
		return nil, errors.Errorf("the port %d is in use", c.Application.Port)
	}

	if !FreeLocalPort(c.Storage.Port) {
		return nil, errors.Errorf("the port %d is in use", c.Application.Port)
	}

	if c.Application.Mode != configs.App_Mode_Release && c.Application.Mode != configs.App_Mode_Debug {
		return nil, errors.New("invalid application mode")
	}

	if c.Access.Mode != configs.Access_Public && c.Access.Mode != configs.Access_Private {
		return nil, errors.New("invalid access mode")
	}

	err = os.MkdirAll(c.Workspace, 0755)
	if err != nil {
		return nil, errors.Errorf("create workspace: %v", err)
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
