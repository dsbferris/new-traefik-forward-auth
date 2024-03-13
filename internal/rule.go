package tfa

import (
	"errors"
	"strings"

	"github.com/dsbferris/traefik-forward-auth/types"
)

// Rule holds defined rules
type Rule struct {
	Action    string
	Rule      string
	Provider  string
	Whitelist types.CommaSeparatedList
	Domains   types.CommaSeparatedList
}

// NewRule creates a new rule object
func NewRule() *Rule {
	return &Rule{
		Action: "auth",
	}
}

func (r *Rule) formattedRule() string {
	// Traefik implements their own "Host" matcher and then offers "HostRegexp"
	// to invoke the mux "Host" matcher. This ensures the mux version is used
	return strings.ReplaceAll(r.Rule, "Host(", "HostRegexp(")
}

// Validate validates a rule
func (r *Rule) Validate(c *Config) error {
	if r.Action != "auth" && r.Action != "soft-auth" && r.Action != "allow" {
		return errors.New("invalid rule action, must be \"auth\", \"soft-auth\", or \"allow\"")
	}

	return c.setupProvider(r.Provider)
}
