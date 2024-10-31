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
	"time"

	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	cess "github.com/CESSProject/cess-go-sdk"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// statCmd is an implementation of the stat command,
// which is used to view the base information of deoss.
func statCmd(cmd *cobra.Command, args []string) {
	var (
		err error
		n   = node.NewEmptyNode()
	)

	n.Config, err = buildConfigFileNotCheck(cmd)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	n.Chainer, err = cess.New(
		context.Background(),
		cess.Name(configs.Name),
		cess.ConnectRpcAddrs(n.Config.Chain.Rpc),
		cess.Mnemonic(n.Config.Chain.Mnemonic),
		cess.TransactionTimeout(time.Second*time.Duration(n.Config.Chain.Timeout)),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer n.Chainer.Close()

	ossinfo, err := n.QueryOss(n.GetSignatureAccPulickey(), -1)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			log.Printf("[err] You are not registered as an oss role\n")
		} else {
			log.Printf("[err] %v\n", chain.ERR_RPC_CONNECTION)
		}
		os.Exit(1)
	}
	var tableRows = []table.Row{
		{"role", "deoss"},
		{"signature account", n.GetSignatureAcc()},
		{"domain name", string(ossinfo.Domain)},
	}
	tw := table.NewWriter()
	tw.AppendRows(tableRows)
	fmt.Println(tw.Render())
	os.Exit(0)
}

func buildConfigFileNotCheck(cmd *cobra.Command) (*confile.Config, error) {
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

	return confile.NewConfigNotCheck(conFilePath)
}
