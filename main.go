package main

import (
	"fmt"
	"net/http"

	"github.com/dsbferris/traefik-forward-auth/appconfig"
	"github.com/dsbferris/traefik-forward-auth/logging"
	"github.com/dsbferris/traefik-forward-auth/tfa"
)

func main() {
	config := appconfig.NewGlobalConfig()
	logger := logging.NewLogger(config.LogFormat, config.LogLevel)

	config.Validate(logger)

	server := tfa.NewServer(logger, config)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	logger.WithField("config", config).Debug("Starting with config")
	logger.Infof("Listening on :%d", config.Port)
	logger.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
