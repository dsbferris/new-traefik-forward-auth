package provider

import (
	"net/url"
	"testing"

	"github.com/dsbferris/new-traefik-forward-auth/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

// Tests

var (
	defaultAuthUrl, _  = types.ParseUrl("https://provider.com/oauth2/auth")
	defaultTokenUrl, _ = types.ParseUrl("https://provider.com/oauth2/token")
	defaultUserUrl, _  = types.ParseUrl("https://provider.com/oauth2/user")
)

func TestGenericOAuthName(t *testing.T) {
	p := GenericOAuth{}
	assert.Equal(t, "generic-oauth", p.Name())
}

func TestGenericOAuthSetup(t *testing.T) {
	assert := assert.New(t)
	p := GenericOAuth{}

	// Check validation
	err := p.Setup()
	if assert.Error(err) {
		assert.Equal(ErrInvalidSetup, err)
	}
	// Check setup
	p = GenericOAuth{
		AuthURL:      defaultAuthUrl,
		TokenURL:     defaultTokenUrl,
		UserURL:      defaultUserUrl,
		ClientID:     "id",
		ClientSecret: "secret",
		TokenStyle:   types.HEADER,
	}
	err = p.Setup()
	assert.Nil(err)
}

func TestGenericOAuthGetLoginURL(t *testing.T) {
	assert := assert.New(t)
	p := GenericOAuth{
		AuthURL:      defaultAuthUrl,
		TokenURL:     defaultTokenUrl,
		UserURL:      defaultUserUrl,
		ClientID:     "idtest",
		ClientSecret: "secret",
		TokenStyle:   types.HEADER,
		OAuthProvider: OAuthProvider{
			Scopes: []string{"scopetest"},
		},
	}
	err := p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	// Check url
	uri, err := url.Parse(p.GetLoginURL("http://example.com/_oauth", "state", false))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("provider.com", uri.Host)
	assert.Equal("/oauth2/auth", uri.Path)

	// Check query string
	qs := uri.Query()
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"state":         []string{"state"},
	}
	assert.Equal(expectedQs, qs)
}

func TestGenericOAuthExchangeCode(t *testing.T) {
	assert := assert.New(t)

	// Setup server
	expected := url.Values{
		"client_id":     []string{"idtest"},
		"client_secret": []string{"sectest"},
		"code":          []string{"code"},
		"grant_type":    []string{"authorization_code"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
	}
	server, serverURL := NewOAuthServer(t, map[string]string{
		"token": expected.Encode(),
	})
	defer server.Close()

	tokenUrl, _ := types.ParseUrl(serverURL.String() + "/token")
	// Setup provider
	p := GenericOAuth{
		AuthURL:      defaultAuthUrl,
		TokenURL:     tokenUrl,
		UserURL:      defaultUserUrl,
		ClientID:     "idtest",
		ClientSecret: "sectest",
		TokenStyle:   types.HEADER,
	}
	err := p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	// We force AuthStyleInParams to prevent the test failure when the
	// AuthStyleInHeader is attempted
	p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	token, err := p.ExchangeCode("http://example.com/_oauth", "code")
	assert.Nil(err)
	assert.Equal("123456789", token)
}

func TestGenericOAuthGetUser(t *testing.T) {
	assert := assert.New(t)

	// Setup server
	server, serverURL := NewOAuthServer(t, nil)
	defer server.Close()

	userUrl, _ := types.ParseUrl(serverURL.String() + "/userinfo")
	// Setup provider
	p := GenericOAuth{
		AuthURL:      defaultAuthUrl,
		TokenURL:     defaultTokenUrl,
		UserURL:      userUrl,
		ClientID:     "idtest",
		ClientSecret: "sectest",
		TokenStyle:   types.HEADER,
	}
	err := p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	// We force AuthStyleInParams to prevent the test failure when the
	// AuthStyleInHeader is attempted
	p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	user, err := p.GetUser("123456789", "email")
	assert.Nil(err)

	assert.Equal("example@example.com", user)
}
