/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"log"
	"os"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	sdkgo "github.com/CESSProject/cess-go-sdk"
	sconfig "github.com/CESSProject/cess-go-sdk/config"
	"github.com/spf13/cobra"
)

// cmd_exit_func is an implementation of the exit command,
// which is used to unregister the deoss role.
func cmd_exit_func(cmd *cobra.Command, args []string) {
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

	txhash, err := n.ExitDeoss()
	if err != nil || txhash == "" {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}

	log.Printf("[OK] %v\n", txhash)
	os.Exit(0)
}
