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
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	sutils "github.com/CESSProject/cess-go-sdk/utils"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	ProfileDefault  = "conf.yaml"
	ProfileTemplete = `# The rpc endpoint of the chain node
Rpc:
  # test network
  - "wss://testnet-rpc0.cess.cloud/ws/"
  - "wss://testnet-rpc1.cess.cloud/ws/"
  - "wss://testnet-rpc2.cess.cloud/ws/"
# Bootstrap Nodes
Boot:
  # test network
  - "_dnsaddr.boot-bucket-testnet.cess.cloud"
# Account mnemonic
Mnemonic: "xxx ... xxx"
# Service workspace
Workspace: "/"
# P2P communication port
P2P_Port: 4001
# Service listening port
HTTP_Port: 8080
# Access mode: public / private
# In public mode, only users in Accounts can't access it. 
# In private mode, only users in Accounts can access it.
Access: public
# Account black/white list
Accounts:
  - cX...
  - cX...
# If you want to expose your oss service, please configure its domain name
Domain: ""`
)

type Confile interface {
	Parse(fpath string) error
	GetRpcAddr() []string
	GetBootNodes() []string
	GetHttpPort() int
	GetP2pPort() int
	GetWorkspace() string
	GetMnemonic() string
	GetPublickey() ([]byte, error)
	GetAccount() string
	GetAccess() string
	GetAccounts() []string
	GetDomainName() string
}

type confile struct {
	Rpc       []string `name:"Rpc" toml:"Rpc" yaml:"Rpc"`
	Boot      []string `name:"Boot" toml:"Boot" yaml:"Boot"`
	Mnemonic  string   `name:"Mnemonic" toml:"Mnemonic" yaml:"Mnemonic"`
	Workspace string   `name:"Workspace" toml:"Workspace" yaml:"Workspace"`
	P2P_Port  int      `name:"P2P_Port" toml:"P2P_Port" yaml:"P2P_Port"`
	HTTP_Port int      `name:"HTTP_Port" toml:"HTTP_Port" yaml:"HTTP_Port"`
	Access    string   `name:"Access" toml:"Access" yaml:"Access"`
	Accounts  []string `name:"Accounts" toml:"Accounts" yaml:"Accounts"`
	Domain    string   `name:"Domain" toml:"Domain" yaml:"Domain"`
}

var _ Confile = (*confile)(nil)

func NewConfigfile() *confile {
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
		return errors.Errorf("Configuration file format error: %v", err)
	}

	_, err = signature.KeyringPairFromSecret(c.Mnemonic, 0)
	if err != nil {
		return errors.Errorf("Invalid mnemonic: %v", err)
	}

	if len(c.Rpc) == 0 ||
		len(c.Boot) == 0 {
		return errors.New("The configuration file cannot have empty entries")
	}

	if c.HTTP_Port < 1024 || c.P2P_Port < 1024 {
		return errors.Errorf("Prohibit the use of system reserved port")
	}
	if c.HTTP_Port > 65535 || c.P2P_Port > 65535 {
		return errors.New("The port number cannot exceed 65535")
	}

	if c.Access != configs.Access_Public && c.Access != configs.Access_Private {
		return errors.New("Invalid Access")
	}

	var accounts = make(map[string]struct{}, 0)
	for _, v := range c.Accounts {
		err = sutils.VerityAddress(v, sutils.CessPrefix)
		if err != nil {
			continue
		}
		accounts[v] = struct{}{}
	}
	var accountList = make([]string, 0)
	for k, _ := range accounts {
		accountList = append(accountList, k)
	}
	c.Accounts = accountList

	err = sutils.CheckDomain(c.Domain)
	if err != nil {
		return errors.New("Invalid domain name")
	}

	fstat, err = os.Stat(c.Workspace)
	if err != nil {
		err = os.MkdirAll(c.Workspace, pattern.DirMode)
		if err != nil {
			return err
		}
		return nil
	}

	if !fstat.IsDir() {
		return errors.Errorf("The '%v' is not a directory", c.Workspace)
	}

	return nil
}

func (c *confile) SetRpcAddr(rpc []string) {
	c.Rpc = rpc
}

func (c *confile) SetBootNodes(boot []string) {
	c.Boot = boot
}

func (c *confile) SetHttpPort(port int) error {
	if port < 1024 {
		return errors.Errorf("Prohibit the use of system reserved port: %v", port)
	}
	if port > 65535 {
		return errors.New("The port number cannot exceed 65535")
	}
	c.HTTP_Port = port
	return nil
}

func (c *confile) SetP2pPort(port int) error {
	if port < 1024 {
		return errors.Errorf("Prohibit the use of system reserved port: %v", port)
	}
	if port > 65535 {
		return errors.New("The port number cannot exceed 65535")
	}
	c.P2P_Port = port
	return nil
}

func (c *confile) SetWorkspace(workspace string) error {
	fstat, err := os.Stat(workspace)
	if err != nil {
		err = os.MkdirAll(workspace, pattern.DirMode)
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

func (c *confile) GetHttpPort() int {
	return c.HTTP_Port
}

func (c *confile) GetP2pPort() int {
	return c.P2P_Port
}

func (c *confile) GetWorkspace() string {
	return c.Workspace
}

func (c *confile) GetMnemonic() string {
	return c.Mnemonic
}

func (c *confile) GetBootNodes() []string {
	return c.Boot
}

func (c *confile) GetPublickey() ([]byte, error) {
	key, err := signature.KeyringPairFromSecret(c.GetMnemonic(), 0)
	if err != nil {
		return nil, err
	}
	return key.PublicKey, nil
}

func (c *confile) GetAccount() string {
	key, _ := signature.KeyringPairFromSecret(c.GetMnemonic(), 0)
	acc, _ := sutils.EncodePublicKeyAsCessAccount(key.PublicKey)
	return acc
}

func (c *confile) GetDomainName() string {
	return c.Domain
}

func (c *confile) GetAccess() string {
	return c.Access
}

func (c *confile) GetAccounts() []string {
	return c.Accounts
}
