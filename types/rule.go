package types

import (
	"errors"
	"strings"
)

// Rule holds defined rules
type Rule struct {
	Action    string
	Rule      string
	Provider  string
	Whitelist CommaSeparatedList
	Domains   CommaSeparatedList
}

// NewRule creates a new rule object
func NewRule() *Rule {
	return &Rule{
		Action: "auth",
	}
}

func (r *Rule) FormattedRule() string {
	// Traefik implements their own "Host" matcher and then offers "HostRegexp"
	// to invoke the mux "Host" matcher. This ensures the mux version is used
	return strings.ReplaceAll(r.Rule, "Host(", "HostRegexp(")
}

// Validate validates a rule
func (r *Rule) Validate(setupProvider func(name string) error) error {
	if r.Action != "auth" && r.Action != "soft-auth" && r.Action != "allow" {
		return errors.New("invalid rule action, must be \"auth\", \"soft-auth\", or \"allow\"")
	}

	return setupProvider(r.Provider)
}
