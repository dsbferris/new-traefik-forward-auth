package main

import (
	"log"

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
	logger, err := logging.NewLogger(config.Log.Format, config.Log.Level)
	if err != nil {
		log.Fatal(err)
	}

	s := server.NewServer(logger, config)
	s.Start()
}
