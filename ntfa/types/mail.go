package types

import (
	"net/mail"
	"strings"
)

type EmailList []*mail.Address

func (emailList *EmailList) String() string {
	var sb strings.Builder
	for i, u := range *emailList {
		sb.WriteString(u.String())
		if i < len(*emailList)-1 {
			sb.WriteString(",")
		}
	}
	return sb.String()
}

func (emailList *EmailList) Set(value string) error {
	var err error
	*emailList, err = mail.ParseAddressList(value)
	return err
}
