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
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	cess "github.com/CESSProject/cess-go-sdk"
	"github.com/spf13/cobra"
)

// exitCmd is an implementation of the exit command,
// which is used to unregister the deoss role.
func exitCmd(cmd *cobra.Command, args []string) {
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

	err = n.InitExtrinsicsNameForOSS()
	if err != nil {
		log.Println("The rpc address does not match the software version, please check the rpc address.")
		os.Exit(1)
	}

	txhash, err := n.DestroyOss()
	if err != nil || txhash == "" {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}

	log.Printf("[OK] %v\n", txhash)
	os.Exit(0)
}
