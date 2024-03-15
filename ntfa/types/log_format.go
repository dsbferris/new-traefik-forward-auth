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

func (f LogFormat) MarshalText() ([]byte, error) {
	var lf string
	switch f {
	case PRETTY:
		lf = "pretty"
	case TEXT:
		lf = "text"
	case JSON:
		lf = "json"
	default:
		return nil, fmt.Errorf("unkown log format: %d", f)
	}
	return []byte(lf), nil
}

func (f LogFormat) String() string {
	b, _ := f.MarshalText()
	return string(b)
}

func (f *LogFormat) UnmarshalText(b []byte) error {
	switch strings.ToLower(string(b)) {
	case "pretty":
		*f = PRETTY
	case "text":
		*f = TEXT
	case "json":
		*f = JSON
	default:
		return fmt.Errorf("unkown log format: %d", f)
	}
	return nil
}
