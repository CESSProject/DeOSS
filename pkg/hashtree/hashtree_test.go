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
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHashTree(t *testing.T) {

	var err error
	var content_one = "content_one"
	var content_two = "content_two"
	var content_three = "content_three"
	var content_four = "content_four"
	var content_one_hash = sha256.Sum256([]byte(content_one))
	var content_two_hash = sha256.Sum256([]byte(content_two))
	var content_three_hash = sha256.Sum256([]byte(content_three))
	var content_four_hash = sha256.Sum256([]byte(content_four))

	var content_five = make([]byte, 0)
	var content_sex = make([]byte, 0)
	content_five = append(content_five, content_one_hash[:]...)
	content_five = append(content_five, content_two_hash[:]...)
	content_sex = append(content_sex, content_three_hash[:]...)
	content_sex = append(content_sex, content_four_hash[:]...)
	hash_five := sha256.Sum256(content_five)
	hash_sex := sha256.Sum256(content_sex)
	var content_seven = make([]byte, 0)
	content_seven = append(content_seven, hash_five[:]...)
	content_seven = append(content_seven, hash_sex[:]...)
	arrhashs := sha256.Sum256(content_seven)
	var roothashs = make([]byte, 0)
	for _, ele := range arrhashs {
		roothashs = append(roothashs, ele)
	}
	var want_root_hash = hex.EncodeToString(roothashs)

	basedir, err := os.Getwd()
	assert.NoError(t, err)
	file_content_one := filepath.Join(basedir, content_one)
	file_content_two := filepath.Join(basedir, content_two)
	file_content_three := filepath.Join(basedir, content_three)
	file_content_four := filepath.Join(basedir, content_four)
	err = os.WriteFile(file_content_one, []byte(content_one), os.ModePerm)
	assert.NoError(t, err)
	defer os.Remove(file_content_one)
	err = os.WriteFile(file_content_two, []byte(content_two), os.ModePerm)
	assert.NoError(t, err)
	defer os.Remove(file_content_two)
	err = os.WriteFile(file_content_three, []byte(content_three), os.ModePerm)
	assert.NoError(t, err)
	defer os.Remove(file_content_three)
	err = os.WriteFile(file_content_four, []byte(content_four), os.ModePerm)
	assert.NoError(t, err)
	defer os.Remove(file_content_four)
	var chunks = []string{file_content_one, file_content_two, file_content_three, file_content_four}

	mtree, err := NewHashTree(chunks)
	assert.NoError(t, err)
	got_root_hash := hex.EncodeToString(mtree.MerkleRoot())
	assert.Equal(t, want_root_hash, got_root_hash)
}
