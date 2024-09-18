package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func main() {
	s := gin.Default()
	s.GET("/hello", func(ctx *gin.Context) {
		account := ctx.Request.Header.Get("Account")
		fmt.Println(account)
		ctx.JSON(200, nil)
	})
	s.Run(":8080")
}
