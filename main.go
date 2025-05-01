package main

import (
	"fmt"

	"github.com/Zacky3181V/wireable/authentication"
	"github.com/Zacky3181V/wireable/generator"
	"github.com/gin-gonic/gin"

	docs "github.com/Zacky3181V/wireable/docs"
	swaggerfiles "github.com/swaggo/files"     // swagger embed files
	ginSwagger "github.com/swaggo/gin-swagger" // gin-swagger middleware
)

func setupRouter() *gin.Engine {

	r := gin.Default()

	docs.SwaggerInfo.BasePath = "/api/v1"
	v1 := r.Group("/api/v1")
	{
		login := v1.Group("/authentication")
		{

			login.POST("/login", authentication.LoginHandler)
		}
	}

	protected := r.Group(docs.SwaggerInfo.BasePath)
	{
		protected.Use(authentication.JWTMiddleware())
		protected.GET("/generate", generator.WireGuardHandler)
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	return r
}

// @title Wireable
// @version 1.0
// @description Automation of Zero-Trust connection for Edge Locations
// @host localhost:8080
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @BasePath /api/v1/
func main() {
	fmt.Println("Hello World from Wireable!")
	r := setupRouter()

	r.Run(":8080")
}
