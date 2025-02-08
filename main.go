package main

import (
	"fmt"
	"net/http"
	"wireable/authentication"
	"wireable/generator"
)



func main() {
	fmt.Println("Hello World from Wireable!")
	http.HandleFunc("/login", authentication.LoginHandler)
	http.HandleFunc("/generate", authentication.JWTMiddleware(generator.WireGuardHandler))
	http.ListenAndServe(":8080", nil)
}
