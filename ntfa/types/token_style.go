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

// implements [encoding.TextMarshaler]
func (t TokenStyle) MarshalText() (value []byte, err error) {
	return []byte(t), nil
}

// implements [encoding.TextUnmarshaler]
func (t *TokenStyle) UnmarshalText(value []byte) error {
	return t.Set(string(value))
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
