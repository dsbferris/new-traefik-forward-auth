package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/dsbferris/new-traefik-forward-auth/types"
	"golang.org/x/oauth2"
)

var ErrInvalidSetup error = errors.New("providers.generic-oauth.auth-url, providers.generic-oauth.token-url, providers.generic-oauth.user-url, providers.generic-oauth.client-id, providers.generic-oauth.client-secret, providers.generic-oauth.token-style must be set")

// GenericOAuth provider
// TODO: change to *types.Url
type GenericOAuth struct {
	AuthURL      *types.Url       `long:"auth-url" env:"AUTH_URL" description:"Auth/Login URL"`
	TokenURL     *types.Url       `long:"token-url" env:"TOKEN_URL" description:"Token URL"`
	UserURL      *types.Url       `long:"user-url" env:"USER_URL" description:"URL used to retrieve user info"`
	ClientID     string           `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string           `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	TokenStyle   types.TokenStyle `long:"token-style" env:"TOKEN_STYLE" default:"header" choice:"header" choice:"query" description:"How token is presented when querying the User URL"`

	OAuthProvider
}

// Name returns the name of the provider
func (o *GenericOAuth) Name() string {
	return "generic-oauth"
}

// Setup performs validation and setup
func (o *GenericOAuth) Setup() error {
	// Check parmas
	if o.AuthURL == nil ||
		o.TokenURL == nil ||
		o.UserURL == nil ||
		o.AuthURL.String() == "" ||
		o.TokenURL.String() == "" ||
		o.UserURL.String() == "" ||
		o.ClientID == "" ||
		o.ClientSecret == "" ||
		o.TokenStyle.String() == "" {
		return ErrInvalidSetup
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  o.AuthURL.String(),
			TokenURL: o.TokenURL.String(),
		},
		Scopes: o.Scopes,
	}

	o.ctx = context.Background()

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *GenericOAuth) GetLoginURL(redirectURI, state string, forcePrompt bool) string {
	return o.OAuthGetLoginURL(redirectURI, state, forcePrompt)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *GenericOAuth) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// GetUser uses the given token and returns a UserID
func (o *GenericOAuth) GetUser(token, UserPath string) (string, error) {
	req, err := http.NewRequest("GET", o.UserURL.String(), nil)
	if err != nil {
		return "", err
	}

	if o.TokenStyle == types.HEADER {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	} else if o.TokenStyle == types.QUERY {
		q := req.URL.Query()
		q.Add("access_token", token)
		req.URL.RawQuery = q.Encode()
	} else {
		return "", fmt.Errorf("unkown token style: %s", o.TokenStyle.String())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return GetUserFromReader(resp.Body, UserPath)
}
