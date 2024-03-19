package types

import "strings"

// CookieDomains provides sypport for comma separated list of cookie domains
type CookieDomains []*CookieDomain

func NewCookieDomains(values ...string) (CookieDomains, error) {
	c := CookieDomains{}
	err := c.Set(strings.Join(values, ","))
	return c, err
}

// UnmarshalFlag converts a comma separated list of cookie domains to an array
// of CookieDomains
func (c *CookieDomains) UnmarshalFlag(value string) error {
	return c.Set(value)
}

// MarshalFlag converts an array of CookieDomain to a comma seperated list
func (c *CookieDomains) MarshalFlag() (string, error) {
	return c.String(), nil
}

// implements [flag.Value]
func (c CookieDomains) String() string {
	var domains []string
	for _, d := range c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ",")
}

// implements [flag.Value]
func (c *CookieDomains) Set(value string) error {
	for _, d := range strings.Split(value, ",") {
		if len(d) <= 0 {
			continue
		}
		cookieDomain := NewCookieDomain(d)
		*c = append(*c, cookieDomain)
	}
	return nil
}
