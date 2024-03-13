package tfa

import "github.com/dsbferris/traefik-forward-auth/appconfig"

var config *appconfig.AppConfig

func SetConfig(c *appconfig.AppConfig) {
	config = c
}
