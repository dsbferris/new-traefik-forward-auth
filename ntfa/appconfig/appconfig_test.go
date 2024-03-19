package appconfig

import (
	// "fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dsbferris/new-traefik-forward-auth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/**
 * Tests
 */

func TestNewConfig(t *testing.T) {

	t.Run("validate emtpy config", func(t *testing.T) {
		assert := assert.New(t)
		config, err := NewConfig([]string{})
		assert.Nil(err)
		err = config.Validate()
		if assert.Error(err) {
			assert.Equal(ErrSecretEmpty, err)
		}
	})

	t.Run("validate with invalid path", func(t *testing.T) {

		assert := assert.New(t)
		config, err := NewConfig([]string{
			"--secret=veryverysecret",
			"--providers.google.client-id=id",
			"--providers.google.client-secret=secret",

			"--url-path=_oauthpath",
		})
		assert.Nil(err)
		err = config.Validate()
		if assert.Error(err) {
			assert.Equal(ErrInvalidPath, err, "path must start with a slash slash")
		}
	})

	t.Run("validate with empty header names", func(t *testing.T) {
		assert := assert.New(t)
		config, err := NewConfig([]string{
			"--secret=veryverysecret",
			"--header-names= ",
		})
		assert.Nil(err)
		err = config.Validate()
		if assert.Error(err) {
			assert.Equal(ErrHeaderNamesEmpty, err)
		}
	})

	t.Run("validate with no provider", func(t *testing.T) {
		assert := assert.New(t)
		config, err := NewConfig([]string{
			"--secret=veryverysecret",
		})
		assert.Nil(err)
		err = config.Validate()
		if assert.Error(err) {
			assert.Equal(ErrNoProvider, err)
		}
	})

	t.Run("validate with multiple providers", func(t *testing.T) {
		assert := assert.New(t)
		config, err := NewConfig([]string{
			"--secret=veryverysecret",
			"--providers.google.client-id=id",
			"--providers.google.client-secret=secret",
			"--providers.oidc.client-id=id",
			"--providers.oidc.client-secret=secret",
			"--providers.oidc.issuer-url=https://accounts.google.com",
		})
		assert.Nil(err)
		err = config.Validate()
		if assert.Error(err) {
			assert.Equal(ErrMultipleProvider, err)
		}
	})

}

func TestConfigDefaults(t *testing.T) {
	assert := assert.New(t)
	config, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",
	})
	assert.Nil(err)
	err = config.Validate()
	assert.Nil(err)

	assert.Equal(types.LEVEL_WARN, config.LogLevel)
	assert.Equal(types.FORMAT_TEXT, config.LogFormat)

	assert.Equal("", config.AuthHost)
	assert.Len(config.CookieDomains, 0)
	assert.False(config.InsecureCookie)
	assert.Equal("_forward_auth", config.CookieName)
	assert.Equal("_forward_auth_csrf", config.CSRFCookieName)
	assert.Equal(&config.Providers.Google, config.SelectedProvider)
	assert.Len(config.Domains, 0)
	assert.Equal([]string{"X-Forwarded-User"}, config.HeaderNames)
	assert.Equal(time.Second*time.Duration(43200), config.Lifetime)
	assert.False(config.MatchWhitelistOrDomain)
	assert.Equal("/_oauth", config.Path)
	assert.Len(config.Whitelist, 0)
	assert.Equal(config.Port, 4181)

	assert.Equal("select_account", config.Providers.Google.Prompt)

	assert.Len(config.TrustedIPNetworks, 0)
}

func TestConfigParseArgs(t *testing.T) {
	assert := assert.New(t)
	config, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.oidc.client-id=id",
		"--providers.oidc.client-secret=secret",
		"--providers.oidc.issuer-url=https://accounts.google.com",

		"--cookie-name=cookiename",
		"--csrf-cookie-name", "csrfcookiename",
		"--port=8000",
		"--lifetime=200s",
	})
	assert.Nil(err)
	err = config.Validate()
	assert.Nil(err)

	// Check normal flags
	assert.Equal("cookiename", config.CookieName)
	assert.Equal("csrfcookiename", config.CSRFCookieName)
	assert.Equal(&config.Providers.OIDC, config.SelectedProvider)
	assert.Equal(8000, config.Port)
	assert.Equal(time.Second*time.Duration(200), config.Lifetime, "lifetime should be read and converted to duration")
}

func TestConfigParseUnknownFlags(t *testing.T) {
	_, err := NewConfig([]string{
		"--unknown=_oauthpath2",
	})

	if assert.Error(t, err) {
		assert.Equal(t, "unknown flag: unknown", err.Error())
	}
}

func TestConfigCommaSeperated(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",

		"--whitelist=test@test.com",
		"--whitelist=test2@test2.com",
	})
	require.Nil(t, err)

	expected1 := []string{"test@test.com", "test2@test2.com"}
	assert.Equal(expected1, c.Whitelist, "should read legacy comma separated list whitelist")
}

func TestConfigParseIni(t *testing.T) {
	assert := assert.New(t)
	configFile1, _ := filepath.Abs("../testfiles/config0")
	configFile2, _ := filepath.Abs("../testfiles/config1")
	c, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",

		"--config=" + configFile1,
		"--config=" + configFile2,
		"--csrf-cookie-name=csrfcookiename",
	})
	require.Nil(t, err)

	assert.Equal("inicookiename", c.CookieName, "should be read from ini file")
	assert.Equal("csrfcookiename", c.CSRFCookieName, "should be read from ini file")
	assert.Equal("/two", c.Path, "variable in second ini file should override first ini file")
}

func TestConfigParseEnvironment(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("COOKIE_NAME", "env_cookie_name")
	os.Setenv("PROVIDERS_GOOGLE_CLIENT_ID", "env_client_id")
	os.Setenv("COOKIE_DOMAIN", "test1.com,example.org")
	os.Setenv("DOMAIN", "test2.com,example.org")
	os.Setenv("WHITELIST", "test3.com,example.org")

	c, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-secret=secret",
	})
	assert.Nil(err)

	assert.Equal("env_cookie_name", c.CookieName, "variable should be read from environment")
	assert.Equal("env_client_id", c.Providers.Google.ClientID, "namespace variable should be read from environment")
	assert.Equal(types.CookieDomains{
		types.NewCookieDomain("test1.com"),
		types.NewCookieDomain("example.org"),
	}, c.CookieDomains, "array variable should be read from environment COOKIE_DOMAIN")
	assert.Equal([]string{"test2.com", "example.org"}, c.Domains, "array variable should be read from environment DOMAIN")
	assert.Equal([]string{"test3.com", "example.org"}, c.Whitelist, "array variable should be read from environment WHITELIST")

	os.Unsetenv("COOKIE_NAME")
	os.Unsetenv("PROVIDERS_GOOGLE_CLIENT_ID")
	os.Unsetenv("COOKIE_DOMAIN")
	os.Unsetenv("DOMAIN")
	os.Unsetenv("WHITELIST")
}

func TestConfigTrustedNetworks(t *testing.T) {
	assert := assert.New(t)

	c, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",

		"--trusted-ip-networks=1.2.3.4,30.1.0.0/16",
	})

	assert.NoError(err)

	table := map[string]bool{
		"1.2.3.3":      false,
		"1.2.3.4":      true,
		"1.2.3.5":      false,
		"192.168.1.1":  false,
		"30.1.0.1":     true,
		"30.1.255.254": true,
		"30.2.0.1":     false,
	}

	for in, want := range table {
		got, err := c.TrustedIPNetworks.ConatainsIp(in)
		assert.NoError(err)
		assert.Equal(want, got, "ip address: %s", in)
	}

}
