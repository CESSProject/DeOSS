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
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"

	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
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

func StringBuilder(cap int, p ...string) string {
	var b strings.Builder
	b.Grow(cap)
	l := len(p)
	for i := 0; i < l; i++ {
		b.WriteString(" " + p[i])
	}
	return b.String()
}

// InterfaceIsNIL returns the comparison between i and nil
func InterfaceIsNIL(i interface{}) bool {
	ret := i == nil
	if !ret {
		defer func() {
			recover()
		}()
		va := reflect.ValueOf(i)
		if va.Kind() == reflect.Ptr {
			return va.IsNil()
		}
		return false
	}
	return ret
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

// Get the total size of all files in a directory and subdirectories
func DirDirs(path string, count uint32) ([]string, error) {
	var dirs = make([]string, 0)
	result, err := filepath.Glob(path + "/*")
	if err != nil {
		return nil, err
	}
	for _, v := range result {
		f, err := os.Stat(v)
		if err != nil {
			continue
		}
		if f.IsDir() {
			dirs = append(dirs, v)
		}
		if count > 0 {
			if len(dirs) >= int(count) {
				break
			}
		}
	}
	return dirs, nil
}

func RenameDir(oldDir, newDir string) error {
	files, err := DirFiles(oldDir, 0)
	if err != nil {
		return err
	}
	fstat, err := os.Stat(newDir)
	if err != nil {
		err = os.MkdirAll(newDir, 0755)
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

func GetDirFreeSpace(dir string) (uint64, error) {
	sageStat, err := disk.Usage(dir)
	return sageStat.Free, err
}

func GetDirUsedSpace(dir string) (uint64, error) {
	sageStat, err := disk.Usage(dir)
	return sageStat.Used, err
}

func GetSysMemAvailable() (uint64, error) {
	var result uint64
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return 0, errors.Wrapf(err, "[mem.VirtualMemory]")
	}
	result = memInfo.Available
	swapInfo, err := mem.SwapMemory()
	if err != nil {
		return result, nil
	}
	return result + swapInfo.Free, nil
}
