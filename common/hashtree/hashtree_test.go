/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
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
	var leafs_num int = 4
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

	basedir, err := os.Getwd()
	assert.NoError(t, err)

	var file_content_one = filepath.Join(basedir, content_one)
	var file_content_two = filepath.Join(basedir, content_two)
	var file_content_three = filepath.Join(basedir, content_three)
	var file_content_four = filepath.Join(basedir, content_four)
	var chunks = []string{file_content_one, file_content_two, file_content_three, file_content_four}

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

	mtree, err := NewHashTree(chunks)
	assert.NoError(t, err)

	// Leaf hash
	assert.Equal(t, len(mtree.Leafs), leafs_num)
	assert.Equal(t, hex.EncodeToString(content_one_hash[:]), hex.EncodeToString(mtree.Leafs[0].Hash))
	assert.Equal(t, hex.EncodeToString(content_two_hash[:]), hex.EncodeToString(mtree.Leafs[1].Hash))
	assert.Equal(t, hex.EncodeToString(content_three_hash[:]), hex.EncodeToString(mtree.Leafs[2].Hash))
	assert.Equal(t, hex.EncodeToString(content_four_hash[:]), hex.EncodeToString(mtree.Leafs[3].Hash))

	// Root hash
	assert.Equal(t, hex.EncodeToString(roothashs), hex.EncodeToString(mtree.MerkleRoot()))
}
