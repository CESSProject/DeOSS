/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"time"

	"github.com/CESSProject/cess-go-sdk/core/pattern"
)

// RecoverError is used to record the stack information of panic
func RecoverError(err interface{}) string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "%v\n", "[panic]")
	fmt.Fprintf(buf, "%v\n", err)
	if debug.Stack() != nil {
		fmt.Fprintf(buf, "%v\n", string(debug.Stack()))
	}
	return buf.String()
}

// RandSlice is used to disrupt the order of elements in the slice
func RandSlice(slice interface{}) {
	rv := reflect.ValueOf(slice)
	if rv.Type().Kind() != reflect.Slice {
		return
	}

	length := rv.Len()
	if length < 2 {
		return
	}

	swap := reflect.Swapper(slice)
	rand.Seed(time.Now().Unix())
	for i := length - 1; i >= 0; i-- {
		j := rand.Intn(length)
		swap(i, j)
	}
	return
}

// InterfaceIsNIL returns the comparison between i and nil
func InterfaceIsNIL(i interface{}) bool {
	ret := i == nil
	if !ret {
		defer func() {
			recover()
		}()
		ret = reflect.ValueOf(i).IsNil()
	}
	return ret
}

// IsIPv4 is used to determine whether ipAddr is an ipv4 address
func IsIPv4(ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	return ip != nil && strings.Contains(ipAddr, ".")
}

// IsIPv6 is used to determine whether ipAddr is an ipv6 address
func IsIPv6(ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	return ip != nil && strings.Contains(ipAddr, ":")
}

func Int64ToBytes(i int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func BytesToInt64(buf []byte) int64 {
	return int64(binary.BigEndian.Uint64(buf))
}

func CopyFile(dst, src string) error {
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}
	return nil
}

// Get the total size of all files in a directory and subdirectories
func DirFiles(path string, count uint32) ([]string, error) {
	var files = make([]string, 0)
	result, err := filepath.Glob(path + "/*")
	if err != nil {
		return nil, err
	}
	for _, v := range result {
		f, err := os.Stat(v)
		if err != nil {
			continue
		}
		if !f.IsDir() {
			files = append(files, v)
		}
		if count > 0 {
			if len(files) >= int(count) {
				break
			}
		}
	}
	return files, nil
}

func RenameDir(oldDir, newDir string) error {
	files, err := DirFiles(oldDir, 0)
	if err != nil {
		return err
	}
	fstat, err := os.Stat(newDir)
	if err != nil {
		err = os.MkdirAll(newDir, pattern.DirMode)
		if err != nil {
			return err
		}
	} else {
		if !fstat.IsDir() {
			return fmt.Errorf("%s not a dir", newDir)
		}
	}

	for _, v := range files {
		name := filepath.Base(v)
		err = os.Rename(filepath.Join(oldDir, name), filepath.Join(newDir, name))
		if err != nil {
			return err
		}
	}

	return os.RemoveAll(oldDir)
}
