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

	"github.com/CESSProject/DeOSS/pkg/confile"
	"github.com/spf13/cobra"
)

// cmd_config_func is an implementation of the config command,
// which is used to generate configuration file.
func cmd_config_func(cmd *cobra.Command, args []string) {
	f, err := os.Create(confile.ProfileDefault)
	if err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	_, err = f.WriteString(confile.ProfileTemplete)
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
		log.Printf("[ok] %v\n", confile.ProfileDefault)
		os.Exit(0)
	}
	path := filepath.Join(pwd, confile.ProfileDefault)
	log.Printf("[ok] %v\n", path)
	os.Exit(0)
}
