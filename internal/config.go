package tfa

import "github.com/dsbferris/traefik-forward-auth/appconfig"

var config *appconfig.Config

func SetConfig(c *appconfig.Config) {
	config = c
}
