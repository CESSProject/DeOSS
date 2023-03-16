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

	"github.com/CESSProject/DeOSS/pkg/chain"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/spf13/cobra"
)

// Command_ State_ Runfunc is used to view basic OSS service information
func Command_State_Runfunc(cmd *cobra.Command, args []string) {
	if len(os.Args) >= 2 {
		// config file
		var configFilePath string
		configpath1, _ := cmd.Flags().GetString("config")
		configpath2, _ := cmd.Flags().GetString("c")
		if configpath1 != "" {
			configFilePath = configpath1
		} else {
			configFilePath = configpath2
		}

		confile := confile.NewConfigfile()
		if err := confile.Parse(configFilePath); err != nil {
			log.Println(err)
			os.Exit(1)
		}

		// chain client
		c, err := chain.NewChainClient(
			confile.GetRpcAddr(),
			confile.GetCtrlPrk(),
			time.Duration(time.Second*15),
		)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		ossState, err := c.GetState(c.GetPublicKey())
		if err != nil || ossState == "" {
			log.Printf("[err] %v\n", err)
			os.Exit(1)
		}
		fmt.Println(ossState)
		os.Exit(0)
	}
	log.Println("[err] Please enter 'scheduler update <ipv4> <port>'")
	os.Exit(1)
}
