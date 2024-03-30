package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dsbferris/new-traefik-forward-auth/appconfig"
	"github.com/dsbferris/new-traefik-forward-auth/logging"
	"github.com/dsbferris/new-traefik-forward-auth/server"
)

func main() {
	healthcheck()

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

func healthcheck() {
	// args
	// program-name healthcheck port
	if len(os.Args) != 3 {
		return
	}
	if strings.ToLower(os.Args[1]) != "healthcheck" {
		return
	}
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		return
	}
	url := fmt.Sprintf("localhost:%d/health", port)
	resp, err := http.Get(url)
	if err != nil {
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		os.Exit(1)
	}
	os.Exit(0)
}
