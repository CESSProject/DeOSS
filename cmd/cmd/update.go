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
	"strconv"
	"time"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/pkg/chain"
	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/CESSProject/DeOSS/pkg/utils"
	"github.com/spf13/cobra"
)

// Generate configuration file template
func Command_Update_Runfunc(cmd *cobra.Command, args []string) {
	if len(os.Args) >= 4 {
		if !utils.IsIPv4(os.Args[2]) {
			log.Println("Please enter 'oss update <ipv4> <port>'")
			os.Exit(1)
		}

		port, err := strconv.Atoi(os.Args[3])
		if err != nil {
			log.Println("Invalid port number")
			os.Exit(1)
		}

		if port < 1025 || port > 65535 {
			log.Println("The port number range is 1025~65535")
			os.Exit(1)
		}

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

		txhash, err := c.Update(os.Args[2], os.Args[3])
		if err != nil {
			if err.Error() == chain.ERR_RPC_EMPTY_VALUE.Error() {
				log.Println("[err] Please check your wallet balance.")
			} else {
				if txhash != "" {
					msg := configs.HELP_common + fmt.Sprintf(" %v\n", txhash)
					msg += configs.HELP_update
					log.Printf("[pending] %v\n", msg)
				} else {
					log.Printf("[err] %v\n", err)
				}
			}
			os.Exit(1)
		}
		log.Println("success")
		os.Exit(0)
	}
	log.Println("[err] Please enter 'scheduler update <ipv4> <port>'")
	os.Exit(1)
}
