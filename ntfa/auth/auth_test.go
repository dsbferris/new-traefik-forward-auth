package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsbferris/new-traefik-forward-auth/appconfig"
	"github.com/dsbferris/new-traefik-forward-auth/provider"
	"github.com/dsbferris/new-traefik-forward-auth/types"
)

/**
 * Tests
 */

var authHost = "auth.example.com"

func newPseudoConfig() *appconfig.AppConfig {
	c, err := appconfig.NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",
	})
	if err != nil {
		panic(err)
	}
	return c
}

func TestAuthValidateCookie(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)

	t.Run("should not pass empty with default", func(t *testing.T) {
		assert := assert.New(t)
		config := newPseudoConfig()
		a := NewAuth(config)

		_, err := a.ValidateCookie(r, &http.Cookie{Value: ""})
		if assert.Error(err) {
			assert.Equal(ErrCookieInvalidFormat, err)
		}
	})

	t.Run("should require 3 parts", func(t *testing.T) {
		assert := assert.New(t)
		config := newPseudoConfig()
		a := NewAuth(config)
		c := &http.Cookie{}

		c.Value = ""
		_, err := a.ValidateCookie(r, c)
		if assert.Error(err) {
			assert.Equal(ErrCookieInvalidFormat, err)
		}
		c.Value = "1|2"
		_, err = a.ValidateCookie(r, c)
		if assert.Error(err) {
			assert.Equal(ErrCookieInvalidFormat, err)
		}
		c.Value = "1|2|3|4"
		_, err = a.ValidateCookie(r, c)
		if assert.Error(err) {
			assert.Equal(ErrCookieInvalidFormat, err)
		}
	})

	t.Run("should catch invalid mac", func(t *testing.T) {
		assert := assert.New(t)
		config := newPseudoConfig()
		a := NewAuth(config)
		c := &http.Cookie{}

		c.Value = "MQ==|2|3"
		_, err := a.ValidateCookie(r, c)
		if assert.Error(err) {
			assert.Equal(ErrCookieInvalidSignature, err)
		}
	})

	t.Run("should catch expired", func(t *testing.T) {
		assert := assert.New(t)
		config := newPseudoConfig()
		config.Cookie.Lifetime = time.Second * time.Duration(-1)
		a := NewAuth(config)

		c := &http.Cookie{}
		c = a.MakeCookie(r, "test@test.com")
		_, err := a.ValidateCookie(r, c)
		if assert.Error(err) {
			assert.Equal(ErrCookieExpired, err)
		}
	})

	t.Run("should accept valid cookie", func(t *testing.T) {
		assert := assert.New(t)
		config := newPseudoConfig()
		config.Cookie.Lifetime = time.Second * time.Duration(10)
		a := NewAuth(config)

		c := &http.Cookie{}
		c = a.MakeCookie(r, "test@test.com")
		email, err := a.ValidateCookie(r, c)
		assert.Nil(err, "valid request should not return an error")
		assert.Equal("test@test.com", email, "valid request should return user email")
	})
}

func TestAuthValidateUser(t *testing.T) {
	assert := assert.New(t)

	t.Run("no whitelisting", func(t *testing.T) {
		config := newPseudoConfig()
		a := NewAuth(config)
		var v bool
		// Should allow any with no whitelist/domain is specified
		v = a.ValidateUser("test@test.com")
		assert.True(v, "should allow any domain if email domain is not defined")
		v = a.ValidateUser("one@two.com")
		assert.True(v, "should allow any domain if email domain is not defined")
	})

	t.Run("domain whitelisting", func(t *testing.T) {
		config := newPseudoConfig()
		config.Whitelist.Domains = []string{"test.com"}
		a := NewAuth(config)
		var v bool

		// Should allow matching domain
		v = a.ValidateUser("one@two.com")
		assert.False(v, "should not allow user from another domain")
		v = a.ValidateUser("test@test.com")
		assert.True(v, "should allow user from allowed domain")

		// Should match regardless of domain case
		v = a.ValidateUser("test@TeSt.com")
		assert.True(v, "should allow user from allowed domain, regardless of case")

	})
	t.Run("user whitelisting", func(t *testing.T) {
		config := newPseudoConfig()
		config.Whitelist.Users = []string{"test@test.com"}
		a := NewAuth(config)
		var v bool
		// Should block non whitelisted email address
		v = a.ValidateUser("one@two.com")
		assert.False(v, "should not allow user not in whitelist")

		// Should allow matching whitelisted email address
		v = a.ValidateUser("one@two.com")
		assert.False(v, "should not allow user not in whitelist")
		v = a.ValidateUser("test@test.com")
		assert.True(v, "should allow user in whitelist")
	})

	t.Run("user and domain whitelisting, no matching either", func(t *testing.T) {

		config := newPseudoConfig()
		config.Whitelist.Domains = []string{"example.com"}
		config.Whitelist.Users = []string{"test@test.com"}
		config.Whitelist.MatchUserOrDomain = false
		a := NewAuth(config)
		var v bool
		// Should allow only matching email address when
		// MatchWhitelistOrDomain is disabled
		v = a.ValidateUser("test@test.com")
		assert.True(v, "should allow user in whitelist")
		v = a.ValidateUser("test@example.com")
		assert.False(v, "should not allow user from valid domain")
		v = a.ValidateUser("one@two.com")
		assert.False(v, "should not allow user not in either")
		v = a.ValidateUser("test@example.com")
		assert.False(v, "should not allow user from allowed domain")
		v = a.ValidateUser("test@test.com")
		assert.True(v, "should allow user in whitelist")

	})

	t.Run("user and domain whitelisting, matching either", func(t *testing.T) {

		config := newPseudoConfig()
		config.Whitelist.Domains = []string{"example.com"}
		config.Whitelist.Users = []string{"test@test.com"}
		config.Whitelist.MatchUserOrDomain = true
		a := NewAuth(config)
		var v bool
		// Should allow either matching domain or email address when
		// MatchWhitelistOrDomain is enabled
		v = a.ValidateUser("one@two.com")
		assert.False(v, "should not allow user not in either")
		v = a.ValidateUser("test@example.com")
		assert.True(v, "should allow user from allowed domain")
		v = a.ValidateUser("test@test.com")
		assert.True(v, "should allow user in whitelist")
		v = a.ValidateUser("test@example.com")
		assert.True(v, "should allow user from valid domain")
	})
}

func TestGetRedirectURI(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		headers map[string]string
		want    string
	}{
		{
			name: "no redirect param",
			path: "/",
			want: "/",
		},
		{
			name: "has redirect param",
			path: "/?redirect=/foo",
			want: "/foo",
		},
		{
			name: "has redirect param from forwarded uri header",
			path: "/",
			headers: map[string]string{
				"X-Forwarded-Uri": "/?redirect=/bar",
			},
			want: "/bar",
		},
	}

	config := newPseudoConfig()
	a := NewAuth(config)
	for _, cc := range cases {
		t.Run(cc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", cc.path, nil)
			require.NoError(t, err)
			for k, v := range cc.headers {
				req.Header.Add(k, v)
			}
			got := a.GetRedirectURI(req)
			assert.Equal(t, cc.want, got)
		})
	}
}

func TestAuthValidateRedirect(t *testing.T) {

	t.Run("validate redirect no auth host", func(t *testing.T) {
		assert := assert.New(t)

		config := newPseudoConfig()
		a := NewAuth(config)
		newRedirectRequest := func(urlStr string) *http.Request {
			u, err := url.Parse(urlStr)
			assert.Nil(err)

			r, _ := http.NewRequest("GET", urlStr, nil)
			r.Header.Add("X-Forwarded-Proto", u.Scheme)
			r.Header.Add("X-Forwarded-Host", u.Host)
			r.Header.Add("X-Forwarded-Uri", u.RequestURI())

			return r
		}

		expectedErr := ErrRedirectHostRequested
		var err error
		_, err = a.ValidateRedirect(
			newRedirectRequest("http://app.example.com/_oauth?state=123"),
			"http://app.example.com.bad.com",
		)
		if assert.Error(err) {
			assert.Equal(expectedErr, err, "Should not allow redirect to subdomain")
		}

		_, err = a.ValidateRedirect(
			newRedirectRequest("http://app.example.com/_oauth?state=123"),
			"http://app.example.combad.com",
		)
		if assert.Error(err) {
			assert.Equal(expectedErr, err, "Should not allow redirect to overlapping domain")
		}

		_, err = a.ValidateRedirect(
			newRedirectRequest("http://app.example.com/_oauth?state=123"),
			"http://example.com",
		)
		if assert.Error(err) {
			assert.Equal(expectedErr, err, "Should not allow redirect from subdomain")
		}

		_, err = a.ValidateRedirect(
			newRedirectRequest("http://app.example.com/_oauth?state=123"),
			"http://app.example.com/profile",
		)
		assert.Nil(err, "Should allow same domain")

	})

	t.Run("validate redirect auth host", func(t *testing.T) {
		assert := assert.New(t)

		config := newPseudoConfig()

		config.AuthHost = authHost
		config.Cookie.Domains = types.CookieDomains{types.NewCookieDomain("example.com")}
		a := NewAuth(config)
		newRedirectRequest := func(urlStr string) *http.Request {
			u, err := url.Parse(urlStr)
			assert.Nil(err)

			r, _ := http.NewRequest("GET", urlStr, nil)
			r.Header.Add("X-Forwarded-Proto", u.Scheme)
			r.Header.Add("X-Forwarded-Host", u.Host)
			r.Header.Add("X-Forwarded-Uri", u.RequestURI())

			return r
		}

		//
		// With Auth Host
		//
		expectedErr := ErrRedirectHostExpected
		var err error

		_, err = a.ValidateRedirect(
			newRedirectRequest("http://app.example.com/_oauth?state=123"),
			"http://app.example.com.bad.com",
		)
		if assert.Error(err) {
			assert.Equal(expectedErr, err, "Should not allow redirect to subdomain")
		}

		_, err = a.ValidateRedirect(
			newRedirectRequest("http://app.example.com/_oauth?state=123"),
			"http://app.example.combad.com",
		)
		if assert.Error(err) {
			assert.Equal(expectedErr, err, "Should not allow redirect to overlapping domain")
		}

		_, err = a.ValidateRedirect(
			newRedirectRequest("http://auth.example.com/_oauth?state=123"),
			"http://app.example.com/profile",
		)
		assert.Nil(err, "Should allow between subdomains when using auth host")

		_, err = a.ValidateRedirect(
			newRedirectRequest("http://auth.example.com/_oauth?state=123"),
			"http://auth.example.com/profile",
		)
		assert.Nil(err, "Should allow same domain when using auth host")

		_, err = a.ValidateRedirect(
			newRedirectRequest("http://auth.example.com/_oauth?state=123"),
			"http://example.com/profile",
		)
		assert.Nil(err, "Should allow from subdomain when using auth host")
	})

}

func TestRedirectUri(t *testing.T) {
	assert := assert.New(t)

	r := httptest.NewRequest("GET", "http://app.example.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "http")

	t.Run("redirect uri no auth host", func(t *testing.T) {
		// No Auth Host

		config := newPseudoConfig()
		a := NewAuth(config)

		uri, err := url.Parse(a.RedirectUri(r))
		assert.Nil(err)
		assert.Equal("http", uri.Scheme)
		assert.Equal("app.example.com", uri.Host)
		assert.Equal("/_oauth", uri.Path)

	})
	t.Run("redirect uri auth host no cookie domain", func(t *testing.T) {

		config := newPseudoConfig()
		config.AuthHost = authHost
		a := NewAuth(config)
		// With Auth URL but no matching cookie domain
		// - will not use auth host

		uri, err := url.Parse(a.RedirectUri(r))
		assert.Nil(err)
		assert.Equal("http", uri.Scheme)
		assert.Equal("app.example.com", uri.Host)
		assert.Equal("/_oauth", uri.Path)

	})
	t.Run("redirect uri auth host", func(t *testing.T) {

		config := newPseudoConfig()
		config.AuthHost = authHost
		config.Cookie.Domains = types.CookieDomains{types.NewCookieDomain("example.com")}
		a := NewAuth(config)
		// With correct Auth URL + cookie domain

		// Check url
		uri, err := url.Parse(a.RedirectUri(r))
		assert.Nil(err)
		assert.Equal("http", uri.Scheme)
		assert.Equal("auth.example.com", uri.Host)
		assert.Equal("/_oauth", uri.Path)

	})

	t.Run("redirect uri auth host cookie different domain", func(t *testing.T) {

		config := newPseudoConfig()
		config.AuthHost = authHost
		config.Cookie.Domains = types.CookieDomains{types.NewCookieDomain("example.com")}
		a := NewAuth(config)
		// With Auth URL + cookie domain, but from different domain
		// - will not use auth host
		r = httptest.NewRequest("GET", "https://another.com/hello", nil)
		r.Header.Add("X-Forwarded-Proto", "https")

		// Check url
		uri, err := url.Parse(a.RedirectUri(r))
		assert.Nil(err)
		assert.Equal("https", uri.Scheme)
		assert.Equal("another.com", uri.Host)
		assert.Equal("/_oauth", uri.Path)
	})

}

func TestAuthMakeCookie(t *testing.T) {
	assert := assert.New(t)

	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	t.Run("make cookie secure", func(t *testing.T) {

		config := newPseudoConfig()
		a := NewAuth(config)

		c := a.MakeCookie(r, "test@example.com")
		assert.Equal("_forward_auth", c.Name)
		parts := strings.Split(c.Value, "|")
		assert.Len(parts, 3, "cookie should be 3 parts")
		_, err := a.ValidateCookie(r, c)
		assert.Nil(err, "should generate valid cookie")
		assert.Equal("/", c.Path)
		assert.Equal("app.example.com", c.Domain)
		assert.True(c.Secure)
		expires := time.Now().Local().Add(config.Cookie.Lifetime)
		assert.WithinDuration(expires, c.Expires, 10*time.Second)
	})

	t.Run("make cookie insecure with name", func(t *testing.T) {

		config := newPseudoConfig()
		config.Cookie.Name = "testname"
		config.Cookie.Insecure = true
		a := NewAuth(config)

		c := a.MakeCookie(r, "test@example.com")
		assert.Equal("testname", c.Name)
		assert.False(c.Secure)
	})

}

func TestAuthMakeCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	t.Run("make csrf cookie", func(t *testing.T) {

		config := newPseudoConfig()
		a := NewAuth(config)
		// No cookie domain or auth url
		c := a.MakeCSRFCookie(r, "12345678901234567890123456789012")
		assert.Equal("_forward_auth_csrf_123456", c.Name)
		assert.Equal("app.example.com", c.Domain)
	})

	t.Run("make csrf cookie with cookie domain, no auth url", func(t *testing.T) {

		config := newPseudoConfig()
		config.Cookie.Domains = types.CookieDomains{types.NewCookieDomain("example.com")}
		a := NewAuth(config)
		// With cookie domain but no auth url
		c := a.MakeCSRFCookie(r, "12222278901234567890123456789012")
		assert.Equal("_forward_auth_csrf_122222", c.Name)
		assert.Equal("app.example.com", c.Domain)
	})

	t.Run("make csrf cookie with cookie domain and auth url", func(t *testing.T) {

		config := newPseudoConfig()
		config.AuthHost = authHost
		config.Cookie.Domains = types.CookieDomains{types.NewCookieDomain("example.com")}
		a := NewAuth(config)
		// With cookie domain and auth url
		c := a.MakeCSRFCookie(r, "12333378901234567890123456789012")
		assert.Equal("_forward_auth_csrf_123333", c.Name)
		assert.Equal("example.com", c.Domain)
	})

}

func TestAuthClearCSRFCookie(t *testing.T) {
	assert := assert.New(t)

	config := newPseudoConfig()
	a := NewAuth(config)
	r, _ := http.NewRequest("GET", "http://example.com", nil)

	c := a.ClearCSRFCookie(r, &http.Cookie{Name: "someCsrfCookie"})
	assert.Equal("someCsrfCookie", c.Name)
	if c.Value != "" {
		t.Error("ClearCSRFCookie should create cookie with empty value")
	}
}

func TestAuthValidateCSRFCookie(t *testing.T) {
	assert := assert.New(t)

	config := newPseudoConfig()
	a := NewAuth(config)
	c := &http.Cookie{}
	state := ""

	// Should require 32 char string
	state = ""
	c.Value = ""
	valid, _, _, err := a.ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal(ErrCsrfInvalidValue, err)
	}
	c.Value = "123456789012345678901234567890123"
	valid, _, _, err = a.ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal(ErrCsrfInvalidValue, err)
	}

	// Should require provider
	state = "12345678901234567890123456789012:99"
	c.Value = "12345678901234567890123456789012"
	valid, _, _, err = a.ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal(ErrCsrfStateFormat, err)
	}

	// Should allow valid state
	state = "12345678901234567890123456789012:p99:url123"
	c.Value = "12345678901234567890123456789012"
	valid, provider, redirect, err := a.ValidateCSRFCookie(c, state)
	assert.True(valid, "valid request should return valid")
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("p99", provider, "valid request should return correct provider")
	assert.Equal("url123", redirect, "valid request should return correct redirect")
}

func TestValidateState(t *testing.T) {
	assert := assert.New(t)

	config := newPseudoConfig()
	a := NewAuth(config)
	// Should require valid state
	state := "12345678901234567890123456789012:"
	err := a.ValidateState(state)
	if assert.Error(err) {
		assert.Equal(ErrCsrfStateValue, err)
	}
	// Should pass this state
	state = "12345678901234567890123456789012:p99:url123"
	err = a.ValidateState(state)
	assert.Nil(err, "valid request should not return an error")
}

func TestMakeState(t *testing.T) {
	assert := assert.New(t)

	config := newPseudoConfig()
	a := NewAuth(config)
	redirect := "http://example.com/hello"

	// Test with google
	p := provider.Google{}
	state := a.MakeState(redirect, &p, "nonce")
	assert.Equal("nonce:google:http://example.com/hello", state)

	// Test with OIDC
	p2 := provider.OIDC{}
	state = a.MakeState(redirect, &p2, "nonce")
	assert.Equal("nonce:oidc:http://example.com/hello", state)

	// Test with Generic OAuth
	p3 := provider.GenericOAuth{}
	state = a.MakeState(redirect, &p3, "nonce")
	assert.Equal("nonce:generic-oauth:http://example.com/hello", state)
}

func TestAuthNonce(t *testing.T) {
	assert := assert.New(t)

	config := newPseudoConfig()
	a := NewAuth(config)
	nonce1, err := a.Nonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce1, 32, "length should be 32 chars")

	nonce2, err := a.Nonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce2, 32, "length should be 32 chars")

	assert.NotEqual(nonce1, nonce2, "nonce should not be equal")
}
