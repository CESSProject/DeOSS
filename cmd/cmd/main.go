/*
   Copyright 2022 CESS scheduler authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package cmd

import (
	"os"

	"github.com/CESSProject/cess-oss/configs"
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
		Command_BuySpace(),
		Command_UpgradePackage(),
		Command_Renewal(),
		Command_Space(),
	)
	rootCmd.PersistentFlags().StringVarP(&configs.ConfigFilePath, "config", "c", "", "Custom profile")
}

func Command_Version() *cobra.Command {
	cc := &cobra.Command{
		Use:                   "version",
		Short:                 "Print version information",
		Run:                   Command_Version_Runfunc,
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
		Short:                 "Operation scheduling service",
		Run:                   Command_Run_Runfunc,
		DisableFlagsInUseLine: true,
	}
	return cc
}

func Command_BuySpace() *cobra.Command {
	cc := &cobra.Command{
		Use:                   "buy",
		Short:                 "Buy space packages:[1, 2, 3, 4, 5]",
		Run:                   Command_BuySpace_Runfunc,
		DisableFlagsInUseLine: true,
	}
	return cc
}

func Command_UpgradePackage() *cobra.Command {
	cc := &cobra.Command{
		Use:                   "upgrade",
		Short:                 "Upgrade a small package to a large package",
		Run:                   Command_UpgradePackage_Runfunc,
		DisableFlagsInUseLine: true,
	}
	return cc
}

func Command_Renewal() *cobra.Command {
	cc := &cobra.Command{
		Use:                   "renewal",
		Short:                 "One-month lease term for additional space package",
		Run:                   Command_Renewal_Runfunc,
		DisableFlagsInUseLine: true,
	}
	return cc
}

func Command_Space() *cobra.Command {
	cc := &cobra.Command{
		Use:                   "space",
		Short:                 "View purchased space details",
		Run:                   Command_Space_Runfunc,
		DisableFlagsInUseLine: true,
	}
	return cc
}
