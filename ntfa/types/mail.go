package types

import (
	"net/mail"
	"strings"
)

type EmailList []*mail.Address

// implements [encoding.TextMarshaler]
func (l EmailList) MarshalText() (value []byte, err error) {
	return []byte(l.String()), nil
}

// implements [encoding.TextUnmarshaler]
func (l *EmailList) UnmarshalText(value []byte) error {
	return l.Set(string(value))
}

// implements [flag.Value]
func (l EmailList) String() string {
	var sb strings.Builder
	for i, u := range l {
		sb.WriteString(u.String())
		if i < len(l)-1 {
			sb.WriteByte(',')
		}
	}
	return sb.String()
}

// implements [flag.Value]
func (l *EmailList) Set(value string) error {
	var err error
	*l, err = mail.ParseAddressList(value)
	return err
}
