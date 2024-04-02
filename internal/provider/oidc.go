package provider

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var ErrMissingIssuerUrl = errors.New("no issuer url provided")

// OIDC provider
type OIDC struct {
	IssuerURL        string `long:"issuer-url" env:"ISSUER_URL" description:"Issuer URL"`
	ClientID         string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientIDFile     string `long:"client-id-file" env:"CLIENT_ID_FILE" description:"Path to a file containing the client id"`
	ClientSecret     string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	ClientSecretFile string `long:"client-secret-file" env:"CLIENT_SECRET_FILE" description:"Path to a file containing the client secret"`

	OAuthProviderConfig

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// Name returns the name of the provider
func (o OIDC) Name() string {
	return "oidc"
}

// Setup performs validation and setup
func (o *OIDC) Setup() error {
	// Check parms
	if o.IssuerURL == "" {
		return ErrMissingIssuerUrl
	}
	if o.ClientID == "" {
		if o.ClientIDFile == "" {
			return ErrMissingClientID
		}
		b, err := os.ReadFile(o.ClientIDFile)
		if err != nil {
			return errors.Join(ErrMissingClientID, err)
		}
		sb := strings.TrimSpace(string(b))
		if sb == "" {
			return ErrMissingClientID
		}
		o.ClientID = sb
	}

	if o.ClientSecret == "" {
		if o.ClientSecretFile == "" {
			return ErrMissingClientSecret
		}
		b, err := os.ReadFile(o.ClientSecretFile)
		if err != nil {
			return errors.Join(ErrMissingClientSecret, err)
		}
		sb := strings.TrimSpace(string(b))
		if sb == "" {
			return ErrMissingClientSecret
		}
		o.ClientSecret = sb
	}
	// TODO valdidate  can be parsed into url
	//url, err := url.Parse(value)

	var err error
	o.ctx = context.Background()

	// Try to initiate provider
	o.provider, err = oidc.NewProvider(o.ctx, o.IssuerURL)
	if err != nil {
		return err
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     o.provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: append([]string{oidc.ScopeOpenID}, o.Scopes...),
	}

	// Create OIDC verifier
	o.verifier = o.provider.Verifier(&oidc.Config{
		ClientID: o.ClientID,
	})

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o OIDC) GetLoginURL(redirectURI, state string, forcePrompt bool) string {
	return o.OAuthGetLoginURL(redirectURI, state, forcePrompt)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o OIDC) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}
	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("missing id_token")
	}
	return rawIDToken, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (o OIDC) GetUser(token, UserPath string) (string, error) {
	// Parse & Verify ID Token
	idToken, err := o.verifier.Verify(o.ctx, token)
	if err != nil {
		return "", err
	}
	// Extract custom claims
	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		return "", err
	}
	return GetUserFromBytes(claims, UserPath)
}
