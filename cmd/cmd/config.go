/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"log"
	"os"
	"path/filepath"

	"github.com/CESSProject/DeOSS/common/confile"
	"github.com/spf13/cobra"
)

// configCmd is an implementation of the config command,
// which is used to generate configuration file.
func configCmd(cmd *cobra.Command, args []string) {
	f, err := os.Create(confile.DefaultConfig)
	if err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	_, err = f.WriteString(confile.ConfigTemplete)
	if err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}
	err = f.Sync()
	if err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}
	pwd, err := os.Getwd()
	if err != nil {
		log.Printf("[ok] %v\n", confile.DefaultConfig)
		os.Exit(0)
	}
	path := filepath.Join(pwd, confile.DefaultConfig)
	log.Printf("[ok] %v\n", path)
	os.Exit(0)
}
