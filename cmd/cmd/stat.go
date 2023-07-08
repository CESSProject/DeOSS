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
	sdkgo "github.com/CESSProject/cess-go-sdk"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
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

	n.SDK, err = sdkgo.New(
		context.Background(),
		sconfig.CharacterName_Deoss,
		sdkgo.ConnectRpcAddrs(n.Confile.GetRpcAddr()),
		sdkgo.Mnemonic(n.Confile.GetMnemonic()),
		sdkgo.TransactionTimeout(configs.TimeOut_WaitBlock),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	pubkey, err := n.Confile.GetPublickey()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	peerPublickey, err := n.QueryDeossPeerPublickey(pubkey)
	if err != nil || peerPublickey == nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}
	var tableRows = []table.Row{
		{"role", n.GetRoleName()},
		{"peer id", base58.Encode(peerPublickey)},
		{"signature account", n.GetSignatureAcc()},
	}
	tw := table.NewWriter()
	tw.AppendRows(tableRows)
	fmt.Println(tw.Render())
	os.Exit(0)
}
