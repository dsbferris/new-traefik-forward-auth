package provider

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/tidwall/gjson"
	"golang.org/x/oauth2"
)

// Providers contains all the implemented providers
type Providers struct {
	Google       Google       `group:"Google Provider" namespace:"google" env-namespace:"GOOGLE"`
	OIDC         OIDC         `group:"OIDC Provider" namespace:"oidc" env-namespace:"OIDC"`
	GenericOAuth GenericOAuth `group:"Generic OAuth2 Provider" namespace:"generic-oauth" env-namespace:"GENERIC_OAUTH"`
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

// OAuthProvider is a provider using the oauth2 library
type OAuthProvider struct {
	Scopes   []string `long:"scope" env:"SCOPE" env-delim:"," default:"profile" default:"email" description:"Scopes"`
	Prompt   string   `long:"prompt" env:"PROMPT" description:"Optional prompt query"`
	Resource string   `long:"resource" env:"RESOURCE" description:"Optional resource indicator"`

	Config *oauth2.Config
	ctx    context.Context
}

// ConfigCopy returns a copy of the oauth2 config with the given redirectURI
// which ensures the underlying config is not modified
func (p *OAuthProvider) ConfigCopy(redirectURI string) oauth2.Config {
	config := *p.Config
	config.RedirectURL = redirectURI
	return config
}

// OAuthGetLoginURL provides a base "GetLoginURL" for proiders using OAauth2
func (p *OAuthProvider) OAuthGetLoginURL(redirectURI, state string, forcePrompt bool) string {
	config := p.ConfigCopy(redirectURI)

	var options []oauth2.AuthCodeOption
	if p.Prompt != "" && !forcePrompt {
		options = append(options, oauth2.SetAuthURLParam("prompt", p.Prompt))
	}
	if p.Resource != "" {
		options = append(options, oauth2.SetAuthURLParam("resource", p.Resource))
	}

	return config.AuthCodeURL(state, options...)
}

// OAuthExchangeCode provides a base "ExchangeCode" for proiders using OAauth2
func (p *OAuthProvider) OAuthExchangeCode(redirectURI, code string) (*oauth2.Token, error) {
	config := p.ConfigCopy(redirectURI)
	return config.Exchange(p.ctx, code)
}
