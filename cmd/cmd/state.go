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
	"fmt"
	"log"
	"os"
	"time"

	"github.com/CESSProject/cess-oss/pkg/chain"
	"github.com/CESSProject/cess-oss/pkg/confile"
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
