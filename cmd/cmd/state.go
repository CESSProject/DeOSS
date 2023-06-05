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
	"time"

	"github.com/CESSProject/DeOSS/node"
	sdkgo "github.com/CESSProject/sdk-go"
	sconfig "github.com/CESSProject/sdk-go/config"
	"github.com/btcsuite/btcutil/base58"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// Command_ State_ Runfunc is used to view basic OSS service information
func Command_State_Runfunc(cmd *cobra.Command, args []string) {
	// config file
	var err error
	var n = node.New()
	// Building profile
	n.Confile, err = buildConfigFile(cmd, "", 0)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	n.SDK, err = sdkgo.New(
		sconfig.CharacterName_Deoss,
		sdkgo.ConnectRpcAddrs(n.Confile.GetRpcAddr()),
		sdkgo.Mnemonic(n.Confile.GetMnemonic()),
		sdkgo.TransactionTimeout(time.Duration(12*time.Second)),
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
	ossState, err := n.QueryDeoss(pubkey)
	if err != nil || ossState == nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}
	var tableRows = []table.Row{
		{"character name", n.GetCharacterName()},
		{"peer id", base58.Encode(ossState)},
		{"signature account", n.GetSignatureAcc()},
	}
	tw := table.NewWriter()
	tw.AppendRows(tableRows)
	fmt.Println(tw.Render())
	os.Exit(0)
}
