/*
   Copyright 2022 CESS (Cumulus Encrypted Storage System) authors

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

package hashtree

import (
	"errors"
	"io"
	"os"

	"github.com/cbergoon/merkletree"
)

// NewHashTree build file to build hash tree
func NewHashTree(chunkPath []string) (*merkletree.MerkleTree, error) {
	if len(chunkPath) == 0 {
		return nil, errors.New("Empty data")
	}
	var list = make([]merkletree.Content, 0)
	for i := 0; i < len(chunkPath); i++ {
		f, err := os.Open(chunkPath[i])
		if err != nil {
			return nil, err
		}
		temp, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		f.Close()
		list = append(list, HashTreeContent{x: string(temp)})
	}

	//Create a new Merkle Tree from the list of Content
	return merkletree.NewTree(list)
}
