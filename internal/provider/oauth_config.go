package provider

import (
	"context"

	"golang.org/x/oauth2"
)

// OAuthProviderConfig is a provider using the oauth2 library
type OAuthProviderConfig struct {
	Scopes   []string `long:"scope" env:"SCOPE" env-delim:"," default:"profile" default:"email" description:"Scopes"`
	Prompt   string   `long:"prompt" env:"PROMPT" description:"Optional prompt query"`
	Resource string   `long:"resource" env:"RESOURCE" description:"Optional resource indicator"`

	Config *oauth2.Config
	ctx    context.Context
}

// ConfigCopy returns a copy of the oauth2 config with the given redirectURI
// which ensures the underlying config is not modified
func (p *OAuthProviderConfig) ConfigCopy(redirectURI string) oauth2.Config {
	config := *p.Config
	config.RedirectURL = redirectURI
	return config
}

// OAuthGetLoginURL provides a base "GetLoginURL" for proiders using OAauth2
func (p *OAuthProviderConfig) OAuthGetLoginURL(redirectURI, state string, forcePrompt bool) string {
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
func (p *OAuthProviderConfig) OAuthExchangeCode(redirectURI, code string) (*oauth2.Token, error) {
	config := p.ConfigCopy(redirectURI)
	return config.Exchange(p.ctx, code)
}
