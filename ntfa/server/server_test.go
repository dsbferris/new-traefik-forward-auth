package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dsbferris/new-traefik-forward-auth/appconfig"
	"github.com/dsbferris/new-traefik-forward-auth/auth"
	"github.com/dsbferris/new-traefik-forward-auth/logging"
	"github.com/dsbferris/new-traefik-forward-auth/types"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

/**
 * Tests
 */

func TestServerRootHandler(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	logger := logging.NewDefaultLogger()

	// X-Forwarded headers should be read into request
	req := httptest.NewRequest("POST", "http://should-use-x-forwarded.com/should?ignore=me", nil)
	req.Header.Add("X-Forwarded-Method", "GET")
	req.Header.Add("X-Forwarded-Proto", "https")
	req.Header.Add("X-Forwarded-Host", "example.com")
	req.Header.Add("X-Forwarded-Uri", "/foo?q=bar")
	NewServer(logger, config).RootHandler(httptest.NewRecorder(), req)

	assert.Equal("GET", req.Method, "x-forwarded-method should be read into request")
	assert.Equal("example.com", req.Host, "x-forwarded-host should be read into request")
	assert.Equal("/foo", req.URL.Path, "x-forwarded-uri should be read into request")
	assert.Equal("/foo?q=bar", req.URL.RequestURI(), "x-forwarded-uri should be read into request")

	// Other X-Forwarded headers should be read in into request and original URL
	// should be preserved if X-Forwarded-Uri not present
	req = httptest.NewRequest("POST", "http://should-use-x-forwarded.com/should-not?ignore=me", nil)
	req.Header.Add("X-Forwarded-Method", "GET")
	req.Header.Add("X-Forwarded-Proto", "https")
	req.Header.Add("X-Forwarded-Host", "example.com")
	NewServer(logger, config).RootHandler(httptest.NewRecorder(), req)

	assert.Equal("GET", req.Method, "x-forwarded-method should be read into request")
	assert.Equal("example.com", req.Host, "x-forwarded-host should be read into request")
	assert.Equal("/should-not", req.URL.Path, "request url should be preserved if x-forwarded-uri not present")
	assert.Equal("/should-not?ignore=me", req.URL.RequestURI(), "request url should be preserved if x-forwarded-uri not present")
}

func TestServerAuthHandlerInvalid(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	a := auth.NewAuth(config)
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.WarnLevel)

	// Should redirect vanilla request to login url
	req := newDefaultHttpRequest("/foo")
	res, _ := doHttpRequest(req, nil, logger, config)
	assert.Equal(307, res.StatusCode, "vanilla request should be redirected")

	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "vanilla request should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "vanilla request should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "vanilla request should be redirected to google")

	// Check state string
	qs := fwd.Query()
	state, exists := qs["state"]
	require.True(t, exists)
	require.Len(t, state, 1)
	parts := strings.SplitN(state[0], ":", 3)
	require.Len(t, parts, 3)
	assert.Equal("google", parts[1])
	assert.Equal("http://example.com/foo", parts[2])

	// Should warn as using http without insecure cookie
	logs := hook.AllEntries()
	assert.Len(logs, 1)
	assert.Equal("You are using \"secure\" cookies for a request that was not "+
		"received via https. You should either redirect to https or pass the "+
		"\"insecure-cookie\" config option to permit cookies via http.", logs[0].Message)
	assert.Equal(logrus.WarnLevel, logs[0].Level)

	// Should catch invalid cookie
	req = newDefaultHttpRequest("/foo")
	c := a.MakeCookie(req, "test@example.com")
	parts = strings.Split(c.Value, "|")
	c.Value = fmt.Sprintf("bad|%s|%s", parts[1], parts[2])

	res, _ = doHttpRequest(req, c, logger, config)
	assert.Equal(401, res.StatusCode, "invalid cookie should not be authorised")

	// Should validate email
	req = newDefaultHttpRequest("/foo")
	c = a.MakeCookie(req, "test@example.com")
	config.Domains = []string{"test.com"}

	res, _ = doHttpRequest(req, c, logger, config)
	assert.Equal(401, res.StatusCode, "invalid email should not be authorised")
}

func TestServerAuthHandlerExpired(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	a := auth.NewAuth(config)
	logger := logging.NewDefaultLogger()
	config.Lifetime = time.Second * time.Duration(-1)
	config.Domains = []string{"test.com"}

	// Should redirect expired cookie
	req := newHTTPRequest("GET", "http://example.com/foo")
	c := a.MakeCookie(req, "test@example.com")
	res, _ := doHttpRequest(req, c, logger, config)
	require.Equal(t, 307, res.StatusCode, "request with expired cookie should be redirected")

	// Check for CSRF cookie
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, config.CSRFCookieName) {
			cookie = c
		}
	}
	assert.NotNil(cookie)

	// Check redirection location
	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "request with expired cookie should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "request with expired cookie should be redirected to google")
}

func TestServerAuthHandlerValid(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	a := auth.NewAuth(config)
	logger := logging.NewDefaultLogger()
	// Should allow valid request email
	req := newHTTPRequest("GET", "http://example.com/foo")
	c := a.MakeCookie(req, "test@example.com")
	config.Domains = []string{}

	res, _ := doHttpRequest(req, c, logger, config)
	assert.Equal(200, res.StatusCode, "valid request should be allowed")

	// Should pass through user
	users := res.Header["X-Forwarded-User"]
	assert.Len(users, 1, "valid request should have X-Forwarded-User header")
	assert.Equal([]string{"test@example.com"}, users, "X-Forwarded-User header should match user")
}

func TestServerAuthHandlerTrustedIP_trusted(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	logger := logging.NewDefaultLogger()

	// Should allow valid request email
	req := newHTTPRequest("GET", "http://example.com/foo")
	req.Header.Set("X-Forwarded-For", "127.0.0.2")

	res, _ := doHttpRequest(req, nil, logger, config)
	assert.Equal(200, res.StatusCode, "trusted ip should be allowed")
}

func TestServerAuthHandlerTrustedIP_notTrusted(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	logger := logging.NewDefaultLogger()

	// Should allow valid request email
	req := newHTTPRequest("GET", "http://example.com/foo")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	res, _ := doHttpRequest(req, nil, logger, config)
	assert.Equal(307, res.StatusCode, "untrusted ip should not be allowed")
}

func TestServerAuthHandlerTrustedIP_invalidAddress(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	logger := logging.NewDefaultLogger()

	// Should allow valid request email
	req := newHTTPRequest("GET", "http://example.com/foo")
	req.Header.Set("X-Forwarded-For", "127.0")

	res, _ := doHttpRequest(req, nil, logger, config)
	assert.Equal(307, res.StatusCode, "invalid ip should not be allowed")
}

func TestServerAuthCallback(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	config := newDefaultConfig()
	a := auth.NewAuth(config)
	logger := logging.NewDefaultLogger()

	// Setup OAuth server
	server, serverURL := NewOAuthServer(t)
	defer server.Close()
	config.Providers.Google.TokenURL = types.Url{URL: &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/token",
	}}
	config.Providers.Google.UserURL = types.Url{URL: &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/userinfo",
	}}

	// Should pass auth response request to callback
	req := newHTTPRequest("GET", "http://example.com/_oauth")
	res, _ := doHttpRequest(req, nil, logger, config)
	assert.Equal(401, res.StatusCode, "auth callback without cookie shouldn't be authorised")

	// Should catch invalid csrf cookie
	nonce := "12345678901234567890123456789012"
	req = newHTTPRequest("GET", "http://example.com/_oauth?state="+nonce+":http://example.com")
	c := a.MakeCSRFCookie(req, "nononononononononononononononono")
	res, _ = doHttpRequest(req, c, logger, config)
	assert.Equal(401, res.StatusCode, "auth callback with invalid cookie shouldn't be authorised")

	// Should catch invalid provider cookie
	req = newHTTPRequest("GET", "http://example.com/_oauth?state="+nonce+":invalid:http://example.com")
	c = a.MakeCSRFCookie(req, nonce)
	res, _ = doHttpRequest(req, c, logger, config)
	assert.Equal(401, res.StatusCode, "auth callback with invalid provider shouldn't be authorised")

	// Should redirect valid request
	req = newHTTPRequest("GET", "http://example.com/_oauth?state="+nonce+":google:http://example.com")
	c = a.MakeCSRFCookie(req, nonce)
	res, _ = doHttpRequest(req, c, logger, config)
	require.Equal(307, res.StatusCode, "valid auth callback should be allowed")

	fwd, _ := res.Location()
	assert.Equal("http", fwd.Scheme, "valid request should be redirected to return url")
	assert.Equal("example.com", fwd.Host, "valid request should be redirected to return url")
	assert.Equal("", fwd.Path, "valid request should be redirected to return url")
}

func TestServerAuthCallbackExchangeFailure(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	a := auth.NewAuth(config)
	logger := logging.NewDefaultLogger()

	// Setup OAuth server
	server, serverURL := NewFailingOAuthServer(t)
	defer server.Close()
	config.Providers.Google.TokenURL = types.Url{URL: &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/token",
	}}
	config.Providers.Google.UserURL = types.Url{URL: &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/userinfo",
	}}

	// Should handle failed code exchange
	req := newDefaultHttpRequest("/_oauth?state=12345678901234567890123456789012:google:http://example.com")
	c := a.MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ := doHttpRequest(req, c, logger, config)
	assert.Equal(503, res.StatusCode, "auth callback should handle failed code exchange")
}

func TestServerAuthCallbackUserFailure(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	a := auth.NewAuth(config)
	logger := logging.NewDefaultLogger()

	// Setup OAuth server
	server, serverURL := NewOAuthServer(t)
	defer server.Close()
	config.Providers.Google.TokenURL = types.Url{URL: &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/token",
	}}
	serverFail, serverFailURL := NewFailingOAuthServer(t)
	defer serverFail.Close()
	config.Providers.Google.UserURL = types.Url{URL: &url.URL{
		Scheme: serverFailURL.Scheme,
		Host:   serverFailURL.Host,
		Path:   "/userinfo",
	}}

	// Should handle failed user request
	req := newDefaultHttpRequest("/_oauth?state=12345678901234567890123456789012:google:http://example.com")
	c := a.MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ := doHttpRequest(req, c, logger, config)
	assert.Equal(503, res.StatusCode, "auth callback should handle failed user request")
}

func TestServerLogout(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	config := newDefaultConfig()
	logger := logging.NewDefaultLogger()

	req := newDefaultHttpRequest("/_oauth/logout")
	res, _ := doHttpRequest(req, nil, logger, config)
	require.Equal(307, res.StatusCode, "should return a 307")

	// Check for cookie
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == config.CookieName {
			cookie = c
		}
	}
	require.NotNil(cookie)
	require.Less(cookie.Expires.Local().Unix(), time.Now().Local().Unix()-50, "cookie should have expired")

	// Test with redirect
	req = newDefaultHttpRequest("/_oauth/logout?redirect=/path")
	res, _ = doHttpRequest(req, nil, logger, config)
	require.Equal(307, res.StatusCode, "should return a 307")

	// Check for cookie
	cookie = nil
	for _, c := range res.Cookies() {
		if c.Name == config.CookieName {
			cookie = c
		}
	}
	require.NotNil(cookie)
	require.Less(cookie.Expires.Local().Unix(), time.Now().Local().Unix()-50, "cookie should have expired")

	fwd, _ := res.Location()
	require.NotNil(fwd)
	assert.Equal("http", fwd.Scheme, "valid request should be redirected to return url")
	assert.Equal("example.com", fwd.Host, "valid request should be redirected to return url")
	assert.Equal("/path", fwd.Path, "valid request should be redirected to return url")

}

func TestServerDefaultAction(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	logger := logging.NewDefaultLogger()

	req := newDefaultHttpRequest("/random")
	res, _ := doHttpRequest(req, nil, logger, config)
	assert.Equal(307, res.StatusCode, "request should require auth with auth default handler")
}

func TestServerDefaultProvider(t *testing.T) {
	assert := assert.New(t)
	config := newDefaultConfig()
	logger := logging.NewDefaultLogger()

	// Should use "google" as default provider when not specified
	req := newDefaultHttpRequest("/random")
	res, _ := doHttpRequest(req, nil, logger, config)
	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "request with expired cookie should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "request with expired cookie should be redirected to google")

	// Should use alternative default provider when set
	config.DefaultProvider = "oidc"
	config.Providers.OIDC.OAuthProvider.Config = &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://oidc.com/oidcauth",
		},
	}

	res, _ = doHttpRequest(req, nil, logger, config)
	fwd, _ = res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to oidc")
	assert.Equal("oidc.com", fwd.Host, "request with expired cookie should be redirected to oidc")
	assert.Equal("/oidcauth", fwd.Path, "request with expired cookie should be redirected to oidc")
}

/**
 * Utilities
 */

type OAuthServer struct {
	t    *testing.T
	fail bool
}

func (s *OAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.fail {
		http.Error(w, "Service unavailable", 500)
		return
	}

	if r.URL.Path == "/token" {
		fmt.Fprintf(w, `{"access_token":"123456789"}`)
	} else if r.URL.Path == "/userinfo" {
		fmt.Fprint(w, `{
			"id":"1",
			"email":"example@example.com",
			"verified_email":true,
			"hd":"example.com"
		}`)
	} else {
		s.t.Fatal("Unrecognised request: ", r.Method, r.URL)
	}
}

func NewOAuthServer(t *testing.T) (*httptest.Server, *url.URL) {
	handler := &OAuthServer{}
	server := httptest.NewServer(handler)
	serverURL, _ := url.Parse(server.URL)
	return server, serverURL
}

func NewFailingOAuthServer(t *testing.T) (*httptest.Server, *url.URL) {
	handler := &OAuthServer{fail: true}
	server := httptest.NewServer(handler)
	serverURL, _ := url.Parse(server.URL)
	return server, serverURL
}

func doHttpRequest(r *http.Request, c *http.Cookie, log *logrus.Logger, config *appconfig.AppConfig) (*http.Response, string) {
	w := httptest.NewRecorder()

	// Set cookies on recorder
	if c != nil {
		http.SetCookie(w, c)
	}

	// Copy into request
	for _, c := range w.Header()["Set-Cookie"] {
		r.Header.Add("Cookie", c)
	}

	NewServer(log, config).RootHandler(w, r)

	res := w.Result()
	body, _ := io.ReadAll(res.Body)

	// if res.StatusCode > 300 && res.StatusCode < 400 {
	// 	fmt.Printf("%#v", res.Header)
	// }

	return res, string(body)
}

func newDefaultConfig() *appconfig.AppConfig {
	config, _ := appconfig.NewConfig([]string{
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",
		"--trusted-ip-networks=127.0.0.2",
	})

	// Setup the google providers without running all the config validation
	config.Providers.Google.Setup()

	return config
}

func newDefaultHttpRequest(uri string) *http.Request {
	return newHTTPRequest("GET", "http://example.com"+uri)
}

func newHTTPRequest(method, target string) *http.Request {
	u, _ := url.Parse(target)
	r := httptest.NewRequest(method, target, nil)
	r.Header.Add("X-Forwarded-Method", method)
	r.Header.Add("X-Forwarded-Proto", u.Scheme)
	r.Header.Add("X-Forwarded-Host", u.Host)
	r.Header.Add("X-Forwarded-Uri", u.RequestURI())
	r.Header.Add("X-Forwarded-For", "127.0.0.1")
	return r
}
