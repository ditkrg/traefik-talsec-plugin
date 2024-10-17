package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ditkrg/traefik-talsec-plugin/internal/options"
	"github.com/ditkrg/traefik-talsec-plugin/internal/services"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

func main() {

	var config options.AppiCryptOptions

	directory, err := os.Getwd() //get the current directory using the built-in function
	if err != nil {
		fmt.Println(err) //print the error if obtained
	}

	handler.Host.Log(api.LogLevelError, fmt.Sprintf("working directory: %v", directory))

	err = json.Unmarshal(handler.Host.GetConfig(), &config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not unmarshal options: %v", err))
		os.Exit(1)
	}

	if err := config.Validate(); err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("config validation failed: %v", err))
		os.Exit(1)
	}

	var appiCryptService = services.NewAppiCryptService()

	handler.HandleRequestFn = appiCryptService.HandleRequest
}
