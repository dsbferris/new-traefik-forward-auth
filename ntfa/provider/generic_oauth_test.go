package provider

import (
	"net/url"
	"testing"

	"github.com/dsbferris/new-traefik-forward-auth/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

// Tests

const (
	providerAuthUrl  = "https://provider.com/oauth2/auth"
	providerTokenUrl = "https://provider.com/oauth2/token"
	providerUserUrl  = "https://provider.com/oauth2/user"
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
	authUrl, _ := url.Parse(providerAuthUrl)
	tokenUrl, _ := url.Parse(providerTokenUrl)
	userUrl, _ := url.Parse(providerUserUrl)
	// Check setup
	p = GenericOAuth{
		AuthURL:      types.Url{URL: authUrl},
		TokenURL:     types.Url{URL: tokenUrl},
		UserURL:      types.Url{URL: userUrl},
		ClientID:     "id",
		ClientSecret: "secret",
		TokenStyle:   types.HEADER,
	}
	err = p.Setup()
	assert.Nil(err)
}

func TestGenericOAuthGetLoginURL(t *testing.T) {
	assert := assert.New(t)
	authUrl, _ := url.Parse(providerAuthUrl)
	tokenUrl, _ := url.Parse(providerTokenUrl)
	userUrl, _ := url.Parse(providerUserUrl)
	p := GenericOAuth{
		AuthURL:      types.Url{URL: authUrl},
		TokenURL:     types.Url{URL: tokenUrl},
		UserURL:      types.Url{URL: userUrl},
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
	authUrl, _ := url.Parse(providerAuthUrl)
	tokenUrl, _ := url.Parse(serverURL.String() + "/token")
	userUrl, _ := url.Parse(providerUserUrl)
	// Setup provider
	p := GenericOAuth{
		AuthURL:      types.Url{URL: authUrl},
		TokenURL:     types.Url{URL: tokenUrl},
		UserURL:      types.Url{URL: userUrl},
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
	authUrl, _ := url.Parse(providerAuthUrl)
	tokenUrl, _ := url.Parse(providerTokenUrl)
	userUrl, _ := url.Parse(serverURL.String() + "/userinfo")
	// Setup provider
	p := GenericOAuth{
		AuthURL:      types.Url{URL: authUrl},
		TokenURL:     types.Url{URL: tokenUrl},
		UserURL:      types.Url{URL: userUrl},
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
