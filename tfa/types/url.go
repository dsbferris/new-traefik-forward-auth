package types

import (
	"net/url"
	"strings"
)

type Url url.URL

func (u Url) String() string {
	return u.ToURL().String()
}

func (u *Url) Set(value string) error {
	p, err := url.Parse(value)
	if err != nil {
		return err
	}
	*u = Url(*p)
	return nil
}

func (u *Url) ToURL() *url.URL {
	url := url.URL(*u)
	return &url
}

type UrlList []*url.URL

func (urlList *UrlList) String() string {
	var sb strings.Builder
	for i, u := range *urlList {
		sb.WriteString(u.String())
		if i < len(*urlList)-1 {
			sb.WriteString(",")
		}
	}
	return sb.String()
}

func (urlList *UrlList) Set(value string) error {
	valueList := strings.Split(value, ",")
	// preallocate size
	*urlList = make(UrlList, 0, len(valueList))
	for _, s := range valueList {
		u, err := url.Parse(s)
		if err != nil {
			return err
		}
		*urlList = append(*urlList, u)
	}
	return nil
}
