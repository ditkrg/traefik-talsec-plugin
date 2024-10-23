package traefik_talsec_plugin

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ditkrg/traefik-talsec-plugin/internal/models"
	"github.com/ditkrg/traefik-talsec-plugin/internal/services"
)

type Talsec struct {
	next             http.Handler
	name             string
	appiCryptService *services.AppiCryptService
}

func CreateConfig() *models.AppiCryptConfig {
	return &models.AppiCryptConfig{}
}

func New(ctx context.Context, next http.Handler, config *models.AppiCryptConfig, name string) (http.Handler, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Talsec{
		next:             next,
		name:             name,
		appiCryptService: services.NewAppiCryptService(config),
	}, nil
}

func (a *Talsec) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	encryptedData := req.Header.Get(a.appiCryptService.Configs.HeaderName)
	if encryptedData == "" {
		msg := fmt.Sprintf("missing appicrypt header, key is %s", a.appiCryptService.Configs.HeaderName)
		http.Error(rw, msg, http.StatusForbidden)
		return
	}

	if err := a.appiCryptService.HandleRequest(&encryptedData, req.Method, req.URL.Path, req.Body); err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}

	a.next.ServeHTTP(rw, req)
}
