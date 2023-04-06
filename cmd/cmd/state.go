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

	"github.com/CESSProject/DeOSS/configs"
	"github.com/CESSProject/DeOSS/node"
	sdkgo "github.com/CESSProject/sdk-go"
	"github.com/spf13/cobra"
)

// Command_ State_ Runfunc is used to view basic OSS service information
func Command_State_Runfunc(cmd *cobra.Command, args []string) {

	// config file
	var err error
	var n = node.New()
	// Building profile
	n.Confile, err = buildConfigFile(cmd)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	n.Cli, err = sdkgo.New(
		configs.Name,
		sdkgo.ConnectRpcAddrs(n.Confile.GetRpcAddr()),
		sdkgo.ListenPort(n.Confile.GetServicePort()),
		sdkgo.Workspace(n.Confile.GetWorkspace()),
	)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	ossState, err := n.Cli.QueryDeoss(n.Confile.GetPublickey())
	if err != nil || ossState == "" {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}
	fmt.Println(ossState)
	os.Exit(0)
}
