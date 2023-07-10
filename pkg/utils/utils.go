package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

func Ternary(a, b int64) int64 {
	if a > b {
		return b
	}
	return a
}

func FindFile(dir, name string) string {
	var result string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Name() == name {
			result = path
		}
		return nil
	})

	if err != nil {
		fmt.Println(err)
	}
	return result
}
