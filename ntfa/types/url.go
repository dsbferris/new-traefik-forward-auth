package types

import (
	"net/url"
)

type Url struct {
	URL *url.URL
}

func ParseUrl(value string) (*Url, error) {
	url, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	return &Url{URL: url}, nil
}

// implements [encoding.TextMarshaler]
func (u Url) MarshalText() (value []byte, err error) {
	return []byte(u.String()), nil
}

// implements [encoding.TextUnmarshaler]
func (u *Url) UnmarshalText(value []byte) error {
	return u.Set(string(value))
}

// implements [flag.Value]
func (u Url) String() string {
	if u.URL == nil {
		return ""
	}
	return u.URL.String()
}

// implements [flag.Value]
func (u *Url) Set(value string) error {
	url, err := url.Parse(value)
	if err != nil {
		return err
	}
	*u = Url{URL: url}
	return nil
}
