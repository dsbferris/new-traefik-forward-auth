package provider

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tidwall/gjson"
)

// Providers contains all the implemented providers
type Providers struct {
	Google       Google       `group:"Google Provider" namespace:"google" env-namespace:"GOOGLE"`
	OIDC         OIDC         `group:"OIDC Provider" namespace:"oidc" env-namespace:"OIDC"`
	GenericOAuth GenericOAuth `group:"Generic OAuth2 Provider" namespace:"generic-oauth" env-namespace:"GENERIC_OAUTH"`
}

func (p Providers) GetAll() []Provider {
	return []Provider{&p.Google, &p.OIDC, &p.GenericOAuth}
}

// Provider is used to authenticate users
type Provider interface {
	Name() string
	GetLoginURL(redirectURI, state string, forcePrompt bool) string
	ExchangeCode(redirectURI, code string) (string, error)
	GetUser(token, UserPath string) (string, error)
	Setup() error
}

type token struct {
	Token string `json:"access_token"`
}

// User is the authenticated user
type User struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

func GetUserFromReader(r io.Reader, UserPath string) (string, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(r)
	if err != nil {
		return "", err
	}
	return GetUserFromBytes(b.Bytes(), UserPath)
}

// GetUser extracts a UserID located at the (dot notation) path (UserPath) in the json io.Reader of the UserURL
func GetUserFromBytes(jsonBytes []byte, UserPath string) (string, error) {
	gjResult := gjson.GetBytes(jsonBytes, UserPath)
	if !gjResult.Exists() {
		return "", fmt.Errorf("no such user path: '%s' in the UserURL response: %s", UserPath, string(jsonBytes))
	}
	return gjResult.String(), nil
}
