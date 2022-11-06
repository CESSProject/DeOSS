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
