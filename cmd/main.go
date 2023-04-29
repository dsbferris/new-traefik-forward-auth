package main

import (
	"fmt"
	"net/http"

	"github.com/traPtitech/traefik-forward-auth/internal"
)

// Main
func main() {
	// Parse options
	config := tfa.NewGlobalConfig()

	// Setup logger
	log := tfa.NewDefaultLogger()

	// Perform config validation
	config.Validate()

	// Build server
	server := tfa.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on :%d", config.Port)
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
