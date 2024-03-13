package main

import (
	"fmt"
	"net/http"

	internal "github.com/traPtitech/traefik-forward-auth/internal"
)

func main() {
	config := internal.NewGlobalConfig()
	log := internal.NewDefaultLogger()

	config.Validate()

	server := internal.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on :%d", config.Port)
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
