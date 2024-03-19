package types

import (
	"fmt"
)

// CookieDomain holds cookie domain info
type CookieDomain struct {
	Domain    string
	SubDomain string
}

// NewCookieDomain creates a new CookieDomain from the given domain string
func NewCookieDomain(domain string) CookieDomain {
	return CookieDomain{
		Domain:    domain,
		SubDomain: fmt.Sprintf(".%s", domain),
	}
}

// Match checks if the given host matches this CookieDomain
func (c *CookieDomain) Match(host string) bool {
	// Exact domain match?
	if host == c.Domain {
		return true
	}

	// Subdomain match?
	return len(host) >= len(c.SubDomain) &&
		host[len(host)-len(c.SubDomain):] == c.SubDomain
}

// UnmarshalFlag converts a string to a CookieDomain
func (c *CookieDomain) UnmarshalFlag(value string) error {
	return c.Set(value)
}

// MarshalFlag converts a CookieDomain to a string
func (c *CookieDomain) MarshalFlag() (string, error) {
	return c.String(), nil
}

// implements [flag.Value]
func (c CookieDomain) String() string {
	return c.Domain
}

// implements [flag.Value]
func (c *CookieDomain) Set(value string) error {
	*c = NewCookieDomain(value)
	return nil
}
