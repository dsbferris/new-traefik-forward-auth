package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/dsbferris/new-traefik-forward-auth/appconfig"
	"github.com/dsbferris/new-traefik-forward-auth/logging"
	"github.com/dsbferris/new-traefik-forward-auth/server"
)

func main() {
	config, err := appconfig.NewDefaultConfig()
	if err != nil {
		log.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		log.Fatal(err)
	}
	logger, err := logging.NewLogger(config.LogFormat, config.LogLevel)
	if err != nil {
		log.Fatal(err)
	}

	s := server.NewServer(logger, config)

	// Attach router to default server
	http.HandleFunc("/", s.RootHandler)

	logger.Debug("Starting with config", slog.String("config", config.String()))
	logger.Info("Listening on ", slog.Int("port", config.Port))
	err = http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil)
	logger.Info("Terminated", slog.String("error", err.Error()))
}
