package main

import (
	"fmt"
	"net/http"

	"github.com/dsbferris/traefik-forward-auth/appconfig"
	internal "github.com/dsbferris/traefik-forward-auth/internal"
	log "github.com/dsbferris/traefik-forward-auth/log"
)

func main() {
	config := appconfig.NewGlobalConfig()
	logger := log.NewDefaultLogger()

	appconfig.ValidateConfig(config, logger)

	internal.SetConfig(config)
	server := internal.NewServer(logger)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	logger.WithField("config", config).Debug("Starting with config")
	logger.Infof("Listening on :%d", config.Port)
	logger.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
