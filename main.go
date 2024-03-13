package main

import (
	"fmt"
	"net/http"

	internal "github.com/dsbferris/traefik-forward-auth/internal"
	log "github.com/dsbferris/traefik-forward-auth/log"
)

func main() {
	config := internal.NewGlobalConfig()
	logger := log.NewDefaultLogger()

	internal.ValidateConfig(config, logger)

	server := internal.NewServer(logger)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	logger.WithField("config", config).Debug("Starting with config")
	logger.Infof("Listening on :%d", config.Port)
	logger.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
