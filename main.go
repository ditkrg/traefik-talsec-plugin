package traefik_talsec_plugin

import (
	"context"
	"log/slog"
	"net/http"
	"os"

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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := config.Validate(); err != nil {
		slog.Error(err.Error())
		return nil, err
	}

	return &Talsec{
		next:             next,
		name:             name,
		appiCryptService: services.NewAppiCryptService(config),
	}, nil
}

func (a *Talsec) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := slog.With("path", req.URL.Path, "method", req.Method)

	if err := a.appiCryptService.HandleRequest(req.Header, req.Method, req.URL.Path, req.Body); err != nil {
		logger.Error(err.Error())
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	a.next.ServeHTTP(rw, req)
}
