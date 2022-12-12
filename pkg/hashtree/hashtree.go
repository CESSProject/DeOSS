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
	"crypto/sha256"

	"github.com/cbergoon/merkletree"
)

// HashTreeContent implements the Content interface provided by merkletree
// and represents the content stored in the tree.
type HashTreeContent struct {
	x string
}

// CalculateHash hashes the values of a HashTreeContent
func (t HashTreeContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents
func (t HashTreeContent) Equals(other merkletree.Content) (bool, error) {
	return t.x == other.(HashTreeContent).x, nil
}
