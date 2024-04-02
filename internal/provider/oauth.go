package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/dsbferris/new-traefik-forward-auth/internal/types"
	_ "github.com/jessevdk/go-flags" // import, so linter knows about multiple definition of choice
	"golang.org/x/oauth2"
)

var ErrInvalidSetup error = errors.New("providers.oauth.auth-url, providers.oauth.token-url, providers.oauth.user-url, providers.oauth.token-style must be set")

// OAuth provider
type OAuth struct {
	AuthURL          string           `long:"auth-url" env:"AUTH_URL" description:"Auth/Login URL"`
	TokenURL         string           `long:"token-url" env:"TOKEN_URL" description:"Token URL"`
	UserURL          string           `long:"user-url" env:"USER_URL" description:"URL used to retrieve user info"`
	ClientID         string           `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientIDFile     string           `long:"client-id-file" env:"CLIENT_ID_FILE" description:"Path to a file containing the client id"`
	ClientSecret     string           `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	ClientSecretFile string           `long:"client-secret-file" env:"CLIENT_SECRET_FILE" description:"Path to a file containing the client secret"`
	TokenStyle       types.TokenStyle `long:"token-style" env:"TOKEN_STYLE" default:"header" choice:"header" choice:"query" description:"How token is presented when querying the User URL"`

	OAuthProviderConfig
}

// Name returns the name of the provider
func (o OAuth) Name() string {
	return "oauth"
}

// Setup performs validation and setup
func (o *OAuth) Setup() error {
	// Check parmas
	if o.AuthURL == "" ||
		o.TokenURL == "" ||
		o.UserURL == "" ||
		o.TokenStyle.String() == "" {
		return ErrInvalidSetup
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

	// TODO add token style auto
	var authStyle oauth2.AuthStyle = oauth2.AuthStyleAutoDetect
	if o.TokenStyle == types.HEADER {
		authStyle = oauth2.AuthStyleInHeader
	} else if o.TokenStyle == types.QUERY {
		authStyle = oauth2.AuthStyleInParams
	}
	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   o.AuthURL,
			TokenURL:  o.TokenURL,
			AuthStyle: authStyle,
		},
		Scopes: o.Scopes,
	}

	o.ctx = context.Background()

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o OAuth) GetLoginURL(redirectURI, state string, forcePrompt bool) string {
	return o.OAuthGetLoginURL(redirectURI, state, forcePrompt)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o OAuth) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// GetUser uses the given token and returns a UserID
func (o OAuth) GetUser(token, UserPath string) (string, error) {
	req, err := http.NewRequest("GET", o.UserURL, nil)
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
