package services

import (
	"github.com/ditkrg/traefik-talsec-plugin/internal/models"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

type AppiCryptService struct {
	Configs *models.AppiCryptConfig
}

func NewAppiCryptService(configs *models.AppiCryptConfig) *AppiCryptService {
	return &AppiCryptService{
		Configs: configs,
	}
}

func (a *AppiCryptService) HandleRequest(req api.Request, resp api.Response) (next bool, reqCtx uint32) {
	return true, 0
}
