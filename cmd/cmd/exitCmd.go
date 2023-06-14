/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"log"
	"os"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	sdkgo "github.com/CESSProject/cess-go-sdk"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/spf13/cobra"
)

// Command_Exit_Runfunc Runfunc is used to unregister the deoss role
func Command_Exit_Runfunc(cmd *cobra.Command, args []string) {
	// config file
	var err error
	var n = node.New()
	// Building profile
	n.Confile, err = buildAuthenticationConfig(cmd)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	n.SDK, err = sdkgo.New(
		sconfig.CharacterName_Deoss,
		sdkgo.ConnectRpcAddrs(n.Confile.GetRpcAddr()),
		sdkgo.Mnemonic(n.Confile.GetMnemonic()),
		sdkgo.TransactionTimeout(configs.TimeOut_WaitBlock),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	txhash, err := n.Exit(n.GetRoleName())
	if err != nil || txhash == "" {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}

	log.Printf("[OK] %v\n", txhash)
	os.Exit(0)
}
