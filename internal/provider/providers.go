package provider

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tidwall/gjson"
)

// Providers contains all the implemented providers
type Providers struct {
	OIDC  OIDC  `group:"OIDC Provider" namespace:"oidc" env-namespace:"OIDC"`
	OAuth OAuth `group:"Generic OAuth2 Provider" namespace:"oauth" env-namespace:"OAUTH"`
}

func (p *Providers) GetAll() []Provider {
	return []Provider{&p.OIDC, &p.OAuth}
}

// Provider is used to authenticate users
type Provider interface {
	Name() string
	GetLoginURL(redirectURI, state string, forcePrompt bool) string
	ExchangeCode(redirectURI, code string) (string, error)
	GetUser(token, UserPath string) (string, error)
	Setup() error
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
