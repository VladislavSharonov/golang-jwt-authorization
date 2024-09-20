package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

func main() {
	ConnectAuthDataBase()
	defer CloseAuthDataBase()
	LoadSecretKeys()

	router := gin.Default()

	// Setup Security Headers
	router.Use(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("Content-Security-Policy", "default-src 'self'; connect-src *; font-src *; script-src-elem * 'unsafe-inline'; img-src * data:; style-src * 'unsafe-inline';")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Referrer-Policy", "strict-origin")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Permissions-Policy", "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()")
		c.Next()
	})

	router.GET("/login", GetNewTokenPair)
	router.POST("/refresh", RefreshJwt)

	err := router.Run("0.0.0.0:8080")
	if err != nil {
		fmt.Println(err)
		return
	}
}
