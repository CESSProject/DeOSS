package handler

import (
	"cess-gateway/configs"
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func Main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AddAllowHeaders("Authorization", "*")
	r.Use(cors.New(config))

	// handler
	r.PUT("/:filename", UpfileHandler)
	r.GET("/:fid", DownfileHandler)
	r.POST("/auth", GrantTokenHandler)
	r.GET("/files", FilelistHandler)
	r.GET("/state/:fid", FilestateHandler)
	r.DELETE("/:fid", DeletefileHandler)

	log.Printf("Start and listen on %v ...", configs.C.ServicePort)
	// run
	r.Run(":" + configs.C.ServicePort)
}
