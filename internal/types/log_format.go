package types

import (
	"fmt"
	"strings"
)

type LogFormat int

const (
	FORMAT_PRETTY LogFormat = iota
	FORMAT_TEXT
	FORMAT_JSON
)

// UnmarshalFlag converts a string to a CookieDomain
func (l *LogFormat) UnmarshalFlag(value string) error {
	return l.Set(value)
}

// MarshalFlag converts a CookieDomain to a string
func (l *LogFormat) MarshalFlag() (string, error) {
	return l.String(), nil
}

// implements [flag.Value]
func (l LogFormat) String() string {
	switch l {
	case FORMAT_PRETTY:
		return "pretty"
	case FORMAT_TEXT:
		return "text"
	case FORMAT_JSON:
		return "json"
	default:
		return ""
	}
}

// implements [flag.Value]
func (l *LogFormat) Set(value string) error {
	switch strings.ToLower(string(value)) {
	case "pretty":
		*l = FORMAT_PRETTY
	case "text":
		*l = FORMAT_TEXT
	case "json":
		*l = FORMAT_JSON
	default:
		return fmt.Errorf("unkown log format: %d", l)
	}
	return nil
}
