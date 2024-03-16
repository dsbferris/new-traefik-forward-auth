package types

import (
	"strings"
)

// CommaSeparatedList provides support for config values provided as csv
type CommaSeparatedList []string

// UnmarshalFlag converts a comma separated list to an array
func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = append(*c, strings.Split(value, ",")...)
	return nil
}

// MarshalFlag converts an array back to a comma separated list
func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}

// implements [encoding.TextMarshaler]
func (c CommaSeparatedList) MarshalText() (value []byte, err error) {
	return []byte(c.String()), nil
}

// implements [encoding.TextUnmarshaler]
func (c *CommaSeparatedList) UnmarshalText(value []byte) error {
	return c.Set(string(value))
}

// implements [flag.Value]
func (c CommaSeparatedList) String() string {
	return strings.Join(c, ",")
}

// implements [flag.Value]
func (c *CommaSeparatedList) Set(value string) error {
	*c = strings.Split(value, ",")
	return nil
}
