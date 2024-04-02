package types

import (
	"net/mail"
	"strings"
)

type EmailList []*mail.Address

// UnmarshalFlag converts a string to a CookieDomain
func (emailList *EmailList) UnmarshalFlag(value string) error {
	return emailList.Set(value)
}

// MarshalFlag converts a CookieDomain to a string
func (emailList *EmailList) MarshalFlag() (string, error) {
	return emailList.String(), nil
}

// implements [flag.Value]
func (emailList EmailList) String() string {
	var sb strings.Builder
	for i, u := range emailList {
		sb.WriteString(u.String())
		if i < len(emailList)-1 {
			sb.WriteByte(',')
		}
	}
	return sb.String()
}

// implements [flag.Value]
func (emailList *EmailList) Set(value string) error {
	for _, e := range strings.Split(value, ",") {
		if len(e) <= 0 {
			continue
		}
		email, err := mail.ParseAddress(e)
		if err != nil {
			return err
		}
		*emailList = append(*emailList, email)
	}
	return nil
}
