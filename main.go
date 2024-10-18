package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ditkrg/traefik-talsec-plugin/internal/models"
	"github.com/ditkrg/traefik-talsec-plugin/internal/services"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

func main() {

	var appiCryptJson models.AppiCryptJson

	err := json.Unmarshal(handler.Host.GetConfig(), &appiCryptJson)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not unmarshal options: %v", err))
		os.Exit(1)
	}

	appiCryptConfig, err := appiCryptJson.ValidateAndConvertToConfig()
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("could not prepare configurations successfully: %v", err))
		os.Exit(1)
	}

	if err := appiCryptConfig.Validate(); err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("config validation failed: %v", err))
		os.Exit(1)
	}

	var appiCryptService = services.NewAppiCryptService(appiCryptConfig)

	handler.HandleRequestFn = appiCryptService.HandleRequest
}
