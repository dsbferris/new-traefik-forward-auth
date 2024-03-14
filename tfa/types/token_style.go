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

func (tokenStyle TokenStyle) MarshalText() ([]byte, error) {
	return []byte(tokenStyle), nil
}

func (tokenStyle TokenStyle) String() string {
	return string(tokenStyle)
}

func (tokenStyle *TokenStyle) Set(value string) error {
	trimmed := TokenStyle(strings.TrimSpace(value))
	switch trimmed {
	case HEADER:
		*tokenStyle = trimmed
	case QUERY:
		*tokenStyle = trimmed
	default:
		return fmt.Errorf("tokenstyle must be one of %s, %s: %s", HEADER, QUERY, trimmed)
	}
	return nil
}

func (tokenStyle *TokenStyle) UnmarshalText(b []byte) error {
	return tokenStyle.Set(string(b))
}
