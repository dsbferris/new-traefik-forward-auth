package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"

	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// Tests

func TestOIDCName(t *testing.T) {
	p := OIDC{}
	assert.Equal(t, "oidc", p.Name())
}

func TestOIDCSetup(t *testing.T) {
	assert := assert.New(t)
	p := OIDC{}

	err := p.Setup()
	if assert.Error(err) {
		assert.Equal("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set", err.Error())
	}
}

func TestOIDCGetLoginURL(t *testing.T) {
	assert := assert.New(t)

	provider, server, serverURL, _, _ := setupOIDCTest(t, nil)
	defer server.Close()

	// Check url
	uri, err := url.Parse(provider.GetLoginURL("http://example.com/_oauth", "state", false))
	assert.Nil(err)
	assert.Equal(serverURL.Scheme, uri.Scheme)
	assert.Equal(serverURL.Host, uri.Host)
	assert.Equal("/auth", uri.Path)

	// Check query string
	qs := uri.Query()
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"openid profile email"},
		"state":         []string{"state"},
	}
	assert.Equal(expectedQs, qs)

	// Calling the method should not modify the underlying config
	assert.Equal("", provider.Config.RedirectURL)

	//
	// Test with resource config option
	//
	provider.Resource = "resourcetest"

	// Check url
	uri, err = url.Parse(provider.GetLoginURL("http://example.com/_oauth", "state", false))
	assert.Nil(err)
	assert.Equal(serverURL.Scheme, uri.Scheme)
	assert.Equal(serverURL.Host, uri.Host)
	assert.Equal("/auth", uri.Path)

	// Check query string
	qs = uri.Query()
	expectedQs = url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"openid profile email"},
		"state":         []string{"state"},
		"resource":      []string{"resourcetest"},
	}
	assert.Equal(expectedQs, qs)

	// Calling the method should not modify the underlying config
	assert.Equal("", provider.Config.RedirectURL)
}

func TestOIDCExchangeCode(t *testing.T) {
	assert := assert.New(t)

	provider, server, _, _, _ := setupOIDCTest(t, map[string]map[string]string{
		"token": {
			"code":         "code",
			"grant_type":   "authorization_code",
			"redirect_uri": "http://example.com/_oauth",
		},
	})
	defer server.Close()

	token, err := provider.ExchangeCode("http://example.com/_oauth", "code")
	assert.Nil(err)
	assert.Equal("id_123456789", token)
}

func TestOIDCGetUser(t *testing.T) {
	assert := assert.New(t)

	provider, server, serverURL, _, priv := setupOIDCTest(t, nil)
	defer server.Close()

	// Generate JWT
	type customClaims struct {
		jwt.RegisteredClaims
		Email         string `json:"email"`
		Username      string `json:"username"`
		EmailVerified bool   `json:"email_verified"`
	}
	claims := customClaims{
		Email:         "example@example.com",
		Username:      "example",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    serverURL.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Audience:  jwt.ClaimStrings{"idtest"},
			Subject:   "1",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims, nil)
	tokenString, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Get username
	username, err := provider.GetUser(tokenString, "username")
	assert.Nil(err)
	assert.Equal("example", username)
	email, err := provider.GetUser(tokenString, "email")
	assert.Nil(err)
	assert.Equal("example@example.com", email)
}

// Utils

// setOIDCTest creates a key, OIDCServer and initilises an OIDC provider
func setupOIDCTest(t *testing.T, bodyValues map[string]map[string]string) (*OIDC, *httptest.Server, *url.URL, ed25519.PublicKey, ed25519.PrivateKey) {
	// Generate key
	pub, priv, err := newEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	body := make(map[string]string)
	// URL encode bodyValues into body
	for method, values := range bodyValues {
		q := url.Values{}
		for k, v := range values {
			q.Set(k, v)
		}
		body[method] = q.Encode()
	}

	// Set up oidc server
	server, serverURL := NewOIDCServerEd25519(t, priv, pub, body)

	// Setup provider
	p := OIDC{
		ClientID:     "idtest",
		ClientSecret: "sectest",
		IssuerURL:    serverURL.String(),
		OAuthProviderConfig: OAuthProviderConfig{
			Scopes: []string{"profile", "email"},
		},
	}

	// Initialise config/verifier
	err = p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	return &p, server, serverURL, pub, priv
}

type OIDCServerEd25519 struct {
	t      *testing.T
	url    *url.URL
	body   map[string]string // method -> body
	key    ed25519.PrivateKey
	pubKey ed25519.PublicKey
}

func NewOIDCServerEd25519(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, body map[string]string) (*httptest.Server, *url.URL) {
	handler := &OIDCServerEd25519{t: t, key: priv, pubKey: pub, body: body}
	server := httptest.NewServer(handler)
	handler.url, _ = url.Parse(server.URL)
	return server, handler.url
}

func (s *OIDCServerEd25519) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	if r.URL.Path == "/.well-known/openid-configuration" {
		// Open id config
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"issuer":"`+s.url.String()+`",
			"authorization_endpoint":"`+s.url.String()+`/auth",
			"token_endpoint":"`+s.url.String()+`/token",
			"jwks_uri":"`+s.url.String()+`/jwks",
			"id_token_signing_alg_values_supported": [
				"`+oidc.EdDSA+`",
				"`+oidc.RS256+`"
			]
		}`)
	} else if r.URL.Path == "/token" {
		// Token request
		// Check body
		if b, ok := s.body["token"]; ok {
			if b != string(body) {
				s.t.Fatal("Unexpected request body, expected", b, "got", string(body))
			}
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"access_token":"123456789",
			"id_token":"id_123456789"
		}`)
	} else if r.URL.Path == "/jwks" {
		// Key request
		w.Header().Set("Content-Type", "application/json")
		//pubJwk := s.key.publicJWK(s.t)
		var jwks struct {
			Keys []*jose.JSONWebKey `json:"keys"`
		}
		jwks.Keys = []*jose.JSONWebKey{
			{
				Key: s.pubKey,
			},
		}
		json, err := json.Marshal(jwks)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		//jwks := `{"keys":[` + pubJwk + `]}`
		w.Write(json)
		//fmt.Fprint(w, response)
	} else {
		s.t.Fatal("Unrecognised request: ", r.URL, string(body))
	}
}

func newEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
