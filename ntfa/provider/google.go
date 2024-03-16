package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/dsbferris/new-traefik-forward-auth/types"
)

// Google provider
type Google struct {
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope        string
	Prompt       string `long:"prompt" env:"PROMPT" default:"select_account" description:"Space separated list of OpenID prompt options"`

	LoginURL types.Url
	TokenURL types.Url
	UserURL  types.Url
}

// Name returns the name of the provider
func (g *Google) Name() string {
	return "google"
}

// Setup performs validation and setup
func (g *Google) Setup() error {
	if g.ClientID == "" || g.ClientSecret == "" {
		return errors.New("providers.google.client-id, providers.google.client-secret must be set")
	}

	// Set static values
	g.Scope = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"

	loginUrl, err := types.ParseUrl("https://accounts.google.com/o/oauth2/auth")
	if err != nil {
		return err
	}
	tokenUrl, err := types.ParseUrl("https://www.googleapis.com/oauth2/v3/token")
	if err != nil {
		return err
	}
	userUrl, err := types.ParseUrl("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return err
	}
	g.LoginURL = loginUrl
	g.TokenURL = tokenUrl
	g.UserURL = userUrl

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (g *Google) GetLoginURL(redirectURI, state string, forcePrompt bool) string {
	q := url.Values{}
	q.Set("client_id", g.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", g.Scope)
	if g.Prompt != "" {
		q.Set("prompt", g.Prompt)
	}
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	u := g.LoginURL.URL
	u.RawQuery = q.Encode()

	return u.String()
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (g *Google) ExchangeCode(redirectURI, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", g.ClientID)
	form.Set("client_secret", g.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)

	res, err := http.PostForm(g.TokenURL.String(), form)
	if err != nil {
		return "", err
	}

	var token token
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&token)

	return token.Token, err
}

// GetUser uses the given token and returns a userID located at the json path
func (g *Google) GetUser(token, UserPath string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", g.UserURL.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	return GetUserFromReader(resp.Body, UserPath)
}
