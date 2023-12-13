package utils

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/multiformats/go-multiaddr"
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
			return nil
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

func RemoveRepeatedAddr(arr []multiaddr.Multiaddr) (newArr []multiaddr.Multiaddr) {
	newArr = make([]multiaddr.Multiaddr, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i].Equal(arr[j]) {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return newArr
}

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
	for i := length - 1; i >= 0; i-- {
		j := rand.New(rand.NewSource(time.Now().Unix())).Intn(length)
		swap(i, j)
	}
}
