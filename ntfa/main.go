package main

import (
	"fmt"
	"net/http"

	"github.com/dsbferris/new-traefik-forward-auth/appconfig"
	"github.com/dsbferris/new-traefik-forward-auth/logging"
	"github.com/dsbferris/new-traefik-forward-auth/server"
)

func main() {
	c := appconfig.NewGlobalConfig()
	l := logging.NewLogger(c.LogFormat, c.LogLevel)

	c.Validate(l)

	s := server.NewServer(l, c)

	// Attach router to default server
	http.HandleFunc("/", s.RootHandler)

	l.WithField("config", c).Debug("Starting with config")
	l.Infof("Listening on :%d", c.Port)
	l.Info(http.ListenAndServe(fmt.Sprintf(":%d", c.Port), nil))
}
