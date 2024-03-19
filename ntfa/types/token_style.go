package types

import (
	"fmt"
	"strings"
)

type TokenStyle string

const (
	HEADER TokenStyle = "header"
	QUERY  TokenStyle = "query"
)

// UnmarshalFlag converts a string to a CookieDomain
func (t *TokenStyle) UnmarshalFlag(value string) error {
	return t.Set(value)
}

// MarshalFlag converts a CookieDomain to a string
func (t *TokenStyle) MarshalFlag() (string, error) {
	return t.String(), nil
}

// implements [flag.Value]
func (t TokenStyle) String() string {
	return string(t)
}

// implements [flag.Value]
func (t *TokenStyle) Set(value string) error {
	v := TokenStyle(strings.ToLower(value))
	switch v {
	case HEADER:
		break
	case QUERY:
		break
	default:
		return fmt.Errorf("tokenstyle must be one of %s, %s. got: %s", HEADER, QUERY, v)
	}
	*t = v
	return nil
}
