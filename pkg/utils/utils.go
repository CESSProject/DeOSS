package utils

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

var regstr = `\d+\.\d+\.\d+\.\d+`
var reg = regexp.MustCompile(regstr)

func FildIpv4(data []byte) (string, bool) {
	result := reg.Find(data)
	return string(result), len(result) > 0
}

func IsIntranetIpv4(ipv4 string) (bool, error) {
	ip := net.ParseIP(ipv4)
	if ip == nil || !strings.Contains(ipv4, ".") {
		return false, errors.New("invalid ipv4")
	}
	if ip.IsLoopback() {
		return true, nil
	}
	if ip.IsPrivate() {
		return true, nil
	}
	return false, nil
}
