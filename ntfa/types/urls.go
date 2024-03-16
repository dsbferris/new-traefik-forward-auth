package types

import (
	"net/url"
	"strings"
)

type Urls []*url.URL

// implements [encoding.TextMarshaler]
func (u Urls) MarshalText() (value []byte, err error) {
	return []byte(u.String()), nil
}

// implements [encoding.TextUnmarshaler]
func (u *Urls) UnmarshalText(value []byte) error {
	return u.Set(string(value))
}

// implements [flag.Value]
func (u Urls) String() string {
	var sb strings.Builder
	for i, url := range u {
		sb.WriteString(url.String())
		if i < len(u)-1 {
			sb.WriteByte(',')
		}
	}
	return sb.String()
}

// implements [flag.Value]
func (u *Urls) Set(value string) error {
	valueList := strings.Split(value, ",")
	urls := make([]*url.URL, len(valueList))
	for i, s := range valueList {
		url, err := url.Parse(s)
		if err != nil {
			return err
		}
		urls[i] = url
	}
	*u = urls
	return nil
}
