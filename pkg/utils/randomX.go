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

package utils

import (
	"math/rand"
	"strings"
	"time"

	"github.com/bwmarrin/snowflake"
)

const (
	letterIdBits = 6
	letterIdMask = 1<<letterIdBits - 1
	letterIdMax  = 63 / letterIdBits
)

const baseStr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()[]{}+-*/_=.<>?:|,~"

// Get a random integer in a specified range
func RandomInRange(min, max int) int {
	time.Sleep(time.Nanosecond)
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}

// Generate random password
func GetRandomcode(length uint8) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano() + rand.Int63()))
	bytes := make([]byte, length)
	l := len(baseStr)
	for i := uint8(0); i < length; i++ {
		bytes[i] = baseStr[r.Intn(l)]
	}
	return string(bytes)
}

func RandStr(n int) string {
	src := rand.NewSource(time.Now().UnixNano())
	sb := strings.Builder{}
	sb.Grow(n)
	// A rand.Int63() generates 63 random bits, enough for letterIdMax letters!
	for i, cache, remain := n-1, src.Int63(), letterIdMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdMax
		}
		if idx := int(cache & letterIdMask); idx < len(baseStr) {
			sb.WriteByte(baseStr[idx])
			i--
		}
		cache >>= letterIdBits
		remain--
	}
	return sb.String()
}

// Get a unique snowflake ID
func GetGuid() (string, error) {
	node, err := snowflake.NewNode(int64(RandomInRange(0, 1024)))
	if err != nil {
		return "", err
	}

	id := node.Generate()
	return id.String(), nil
}
