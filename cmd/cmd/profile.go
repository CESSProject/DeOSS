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
	"log"
	"os"
	"path/filepath"

	"github.com/CESSProject/cess-oss/pkg/confile"
	"github.com/spf13/cobra"
)

// Generate profile template
func Command_Profile_Runfunc(cmd *cobra.Command, args []string) {
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
