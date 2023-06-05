/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"os"

	"github.com/CESSProject/DeOSS/configs"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   configs.Name,
	Short: configs.Description,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// init
func init() {
	rootCmd.AddCommand(
		Command_Profile(),
		Command_Version(),
		Command_Run(),
		Command_State(),
	)
	rootCmd.PersistentFlags().StringP("config", "c", "conf.yaml", "Custom profile")
	rootCmd.PersistentFlags().StringP("rpc", "", "wss://testnet-rpc0.cess.cloud/ws/", "rpc endpoint")
	rootCmd.PersistentFlags().StringP("ws", "", "/", "workspace")
	rootCmd.PersistentFlags().StringP("ip", "", "0.0.0.0", "listening ip address")
	rootCmd.PersistentFlags().IntP("http_port", "P", 8080, "service listening port")
	rootCmd.PersistentFlags().IntP("p2p_port", "p", 15008, "p2p port")
	rootCmd.PersistentFlags().StringP("boot", "", "", "bootstap node")
}

func Command_Version() *cobra.Command {
	cc := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(configs.Version)
			os.Exit(0)
		},
		DisableFlagsInUseLine: true,
	}
	return cc
}

func Command_Profile() *cobra.Command {
	cc := &cobra.Command{
		Use:                   "profile",
		Short:                 "Generate profile template",
		Run:                   Command_Profile_Runfunc,
		DisableFlagsInUseLine: true,
	}
	return cc
}

func Command_Run() *cobra.Command {
	cc := &cobra.Command{
		Use:                   "run",
		Short:                 "Running services",
		Run:                   Command_Run_Runfunc,
		DisableFlagsInUseLine: true,
	}
	return cc
}

func Command_State() *cobra.Command {
	cc := &cobra.Command{
		Use:                   "state",
		Short:                 "View status",
		Run:                   Command_State_Runfunc,
		DisableFlagsInUseLine: true,
	}
	return cc
}
