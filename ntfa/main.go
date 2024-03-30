package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

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
	if len(os.Args) != 3 || strings.ToLower(os.Args[1]) != "healthcheck" {
		return
	}

	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("Error parsing port, %v", err)
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d/health", port), nil)
	if err != nil {
		log.Fatalf("Error creating request, %v", err)
	}
	resp, err := (&http.Client{Timeout: time.Second * 3}).Do(req)
	if err != nil {
		log.Fatalf("Unhealthy, %v", err)
		fmt.Println("Unhealthy, error")
	}
	if resp.StatusCode != 200 {
		log.Fatalln("Unhealthy, non 200")
	}
	log.Println("Healthy")
	os.Exit(0)
}
