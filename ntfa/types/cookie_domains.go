package types

import "strings"

// CookieDomains provides sypport for comma separated list of cookie domains
type CookieDomains []*CookieDomain

// UnmarshalFlag converts a comma separated list of cookie domains to an array
// of CookieDomains
func (c *CookieDomains) UnmarshalFlag(value string) error {
	if len(value) > 0 {
		for _, d := range strings.Split(value, ",") {
			cookieDomain := NewCookieDomain(d)
			*c = append(*c, cookieDomain)
		}
	}
	return nil
}

// MarshalFlag converts an array of CookieDomain to a comma seperated list
func (c *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}

// implements [encoding.TextMarshaler]
func (c CookieDomains) MarshalText() (value []byte, err error) {
	return []byte(c.String()), nil
}

// implements [encoding.TextUnmarshaler]
func (c *CookieDomains) UnmarshalText(value []byte) error {
	return c.Set(string(value))
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
	split := strings.Split(value, ",")
	l := make([]*CookieDomain, len(split))
	for i, d := range split {
		cookieDomain := NewCookieDomain(d)
		l[i] = cookieDomain
	}
	*c = l
	return nil
}
