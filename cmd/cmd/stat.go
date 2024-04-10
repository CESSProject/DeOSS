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

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	cess "github.com/CESSProject/cess-go-sdk"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/CESSProject/cess-go-sdk/core/pattern"
	"github.com/btcsuite/btcutil/base58"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// cmd_stat_func is an implementation of the stat command,
// which is used to view the base information of deoss.
func cmd_stat_func(cmd *cobra.Command, args []string) {
	var (
		err error
		n   = node.New()
	)

	n.Confile, err = buildAuthenticationConfig(cmd)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	n.SDK, err = cess.New(
		context.Background(),
		cess.Name(sconfig.CharacterName_Deoss),
		cess.ConnectRpcAddrs(n.Confile.GetRpcAddr()),
		cess.Mnemonic(n.Confile.GetMnemonic()),
		cess.TransactionTimeout(configs.TimeOut_WaitBlock),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer n.GetSubstrateAPI().Client.Close()

	pubkey, err := n.Confile.GetPublickey()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	ossinfo, err := n.QueryDeOSSInfo(pubkey)
	if err != nil {
		if err.Error() == pattern.ERR_Empty {
			log.Printf("[err] You are not registered as an oss role\n")
		} else {
			log.Printf("[err] %v\n", pattern.ERR_RPC_CONNECTION)
		}
		os.Exit(1)
	}
	var tableRows = []table.Row{
		{"role", "deoss"},
		{"peer id", base58.Encode([]byte(string(ossinfo.Peerid[:])))},
		{"signature account", n.GetSignatureAcc()},
		{"domain name", string(ossinfo.Domain)},
	}
	tw := table.NewWriter()
	tw.AppendRows(tableRows)
	fmt.Println(tw.Render())
	os.Exit(0)
}
