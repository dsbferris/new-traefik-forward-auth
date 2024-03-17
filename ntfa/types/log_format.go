package types

import (
	"fmt"
	"strings"
)

type LogFormat int

const (
	PRETTY LogFormat = iota
	TEXT
	JSON
)

// UnmarshalFlag converts a string to a CookieDomain
func (l *LogFormat) UnmarshalFlag(value string) error {
	return l.Set(value)
}

// MarshalFlag converts a CookieDomain to a string
func (l *LogFormat) MarshalFlag() (string, error) {
	return l.String(), nil
}

// implements [encoding.TextMarshaler]
func (l LogFormat) MarshalText() (value []byte, err error) {
	return []byte(l.String()), nil
}

// implements [encoding.TextUnmarshaler]
func (l *LogFormat) UnmarshalText(value []byte) error {
	return l.Set(string(value))
}

// implements [flag.Value]
func (l LogFormat) String() string {
	switch l {
	case PRETTY:
		return "pretty"
	case TEXT:
		return "text"
	case JSON:
		return "json"
	default:
		return ""
	}
}

// implements [flag.Value]
func (l *LogFormat) Set(value string) error {
	switch strings.ToLower(string(value)) {
	case "pretty":
		*l = PRETTY
	case "text":
		*l = TEXT
	case "json":
		*l = JSON
	default:
		return fmt.Errorf("unkown log format: %d", l)
	}
	return nil
}
