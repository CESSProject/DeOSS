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

package node

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGetHandle(t *testing.T) {
	// test case
	tests := []struct {
		name  string
		param string
	}{
		{"base case", `{"name": "filehash"}`},
		{"bad case", `{"name": "bucket"}`},
		{"bad case", ""},
	}
	node := New()
	node.Handle = gin.Default()
	node.addRoute()
	r := node.Handle
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// mock a http request
			req := httptest.NewRequest(
				"GET",
				"/",
				//strings.NewReader(tt.param),
				nil,
			)
			// mock a recorder
			w := httptest.NewRecorder()
			// handle
			r.ServeHTTP(w, req)
			// resp code
			assert.Equal(t, http.StatusNotFound, w.Code)
			// print body
			fmt.Println(w.Body.String())
		})
	}
}
