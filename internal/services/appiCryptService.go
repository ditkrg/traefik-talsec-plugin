package services

import (
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

type AppiCryptService struct {
	// Opts *options.AppiCryptOptions
}

func NewAppiCryptService() *AppiCryptService {
	return &AppiCryptService{
		// Opts: opts,
	}
}

func (a *AppiCryptService) HandleRequest(req api.Request, resp api.Response) (next bool, reqCtx uint32) {
	return true, 0
}
