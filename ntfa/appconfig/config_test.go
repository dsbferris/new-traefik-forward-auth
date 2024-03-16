package appconfig

import (
	// "fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dsbferris/new-traefik-forward-auth/types"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/**
 * Tests
 */

func TestConfigDefaults(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{})
	assert.Nil(err)

	assert.Equal("warn", c.LogLevel)
	assert.Equal("text", c.LogFormat)

	assert.Equal("", c.AuthHost.String())
	assert.Len(c.CookieDomains, 0)
	assert.False(c.InsecureCookie)
	assert.Equal("_forward_auth", c.CookieName)
	assert.Equal("_forward_auth_csrf", c.CSRFCookieName)
	assert.Equal("google", c.DefaultProvider)
	assert.Len(c.Domains, 0)
	assert.Equal(types.CommaSeparatedList{"X-Forwarded-User"}, c.HeaderNames)
	assert.Equal(time.Second*time.Duration(43200), c.Lifetime)
	assert.False(c.MatchWhitelistOrDomain)
	assert.Equal("/_oauth", c.Path)
	assert.Len(c.Whitelist, 0)
	assert.Equal(c.Port, 4181)
	assert.Len(c.ProbeToken, 0)
	assert.Equal(c.ProbeTokenUser, "probe")

	assert.Equal("select_account", c.Providers.Google.Prompt)

	assert.Len(c.TrustedIPNetworks, 0)
}

func TestConfigParseArgs(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--cookie-name=cookiename",
		"--csrf-cookie-name", "\"csrfcookiename\"",
		"--default-provider", "\"oidc\"",
		"--port=8000",
		"--probe-token=super-secret-token",
		"--probe-token-user=toki",
	})
	require.Nil(t, err)

	// Check normal flags
	assert.Equal("cookiename", c.CookieName)
	assert.Equal("csrfcookiename", c.CSRFCookieName)
	assert.Equal("oidc", c.DefaultProvider)
	assert.Equal(8000, c.Port)
	assert.ElementsMatch(c.ProbeToken, []string{"super-secret-token"})
	assert.Equal(c.ProbeTokenUser, "toki")
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
		"--whitelist=test@test.com,test2@test2.com",
	})
	require.Nil(t, err)

	expected1 := types.CommaSeparatedList{"test@test.com", "test2@test2.com"}
	assert.Equal(expected1, c.Whitelist, "should read legacy comma separated list whitelist")
}

func TestConfigParseIni(t *testing.T) {
	assert := assert.New(t)
	configFile1, _ := filepath.Abs("../testfiles/config0")
	configFile2, _ := filepath.Abs("../testfiles/config1")
	c, err := NewConfig([]string{
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

	c, err := NewConfig([]string{})
	assert.Nil(err)

	assert.Equal("env_cookie_name", c.CookieName, "variable should be read from environment")
	assert.Equal("env_client_id", c.Providers.Google.ClientID, "namespace variable should be read from environment")
	assert.Equal(types.CookieDomains{
		types.NewCookieDomain("test1.com"),
		types.NewCookieDomain("example.org"),
	}, c.CookieDomains, "array variable should be read from environment COOKIE_DOMAIN")
	assert.Equal(types.CommaSeparatedList{"test2.com", "example.org"}, c.Domains, "array variable should be read from environment DOMAIN")
	assert.Equal(types.CommaSeparatedList{"test3.com", "example.org"}, c.Whitelist, "array variable should be read from environment WHITELIST")

	os.Unsetenv("COOKIE_NAME")
	os.Unsetenv("PROVIDERS_GOOGLE_CLIENT_ID")
	os.Unsetenv("COOKIE_DOMAIN")
	os.Unsetenv("DOMAIN")
	os.Unsetenv("WHITELIST")
}

func TestConfigTransformation(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--url-path=_oauthpath",
		"--secret=verysecret",
		"--lifetime=200",
	})
	require.Nil(t, err)

	assert.Equal("/_oauthpath", c.Path, "path should add slash to front")
	assert.Equal("verysecret", c.Secret)
	assert.Equal(200, c.LifetimeString)
	assert.Equal(time.Second*time.Duration(200), c.Lifetime, "lifetime should be read and converted to duration")
}

func TestConfigValidate(t *testing.T) {

	t.Run("validate default config", func(t *testing.T) {

		assert := assert.New(t)
		// Install new logger + hook
		log, hook := test.NewNullLogger()
		log.ExitFunc = func(code int) {}

		// Validate default config
		c, _ := NewConfig([]string{})
		c.Validate(log)

		logs := hook.AllEntries()
		assert.Len(logs, 2)

		// Should have fatal error requiring secret
		assert.Equal("\"secret\" option must be set", logs[0].Message)
		assert.Equal(logrus.FatalLevel, logs[0].Level)

		// Should also have default provider (google) error
		assert.Equal("providers.google.client-id, providers.google.client-secret must be set", logs[1].Message)
		assert.Equal(logrus.FatalLevel, logs[1].Level)

	})
	t.Run("validate with invalid provider", func(t *testing.T) {
		assert := assert.New(t)
		_, err := NewConfig([]string{
			"--secret=veryverysecret",
			"--providers.google.client-id=id",
			"--providers.google.client-secret=secret",
			"--default-provider=bad",
		})
		if assert.Error(err) {
			assert.Equal("Invalid value `bad' for option `--default-provider'. Allowed values are: google, oidc or generic-oauth", err.Error())
		}
	})

	// Validate with invalid providers

}

func TestConfigGetProvider(t *testing.T) {
	assert := assert.New(t)
	c, _ := NewConfig([]string{})

	// Should be able to get "google" provider
	p, err := c.GetProvider("google")
	assert.Nil(err)
	assert.Equal(&c.Providers.Google, p)

	// Should be able to get "oidc" provider
	p, err = c.GetProvider("oidc")
	assert.Nil(err)
	assert.Equal(&c.Providers.OIDC, p)

	// Should be able to get "generic-oauth" provider
	p, err = c.GetProvider("generic-oauth")
	assert.Nil(err)
	assert.Equal(&c.Providers.GenericOAuth, p)

	// Should catch unknown provider
	_, err = c.GetProvider("bad")
	if assert.Error(err) {
		assert.Equal("Unknown provider: bad", err.Error())
	}
}

func TestConfigGetConfiguredProvider(t *testing.T) {
	assert := assert.New(t)
	c, _ := NewConfig([]string{})

	// Should be able to get "google" default provider
	p, err := c.GetConfiguredProvider("google")
	assert.Nil(err)
	assert.Equal(&c.Providers.Google, p)

	// Should fail to get valid "oidc" provider as it's not configured
	_, err = c.GetConfiguredProvider("oidc")
	if assert.Error(err) {
		assert.Equal("Unconfigured provider: oidc", err.Error())
	}
}

func TestConfigCommaSeparatedList(t *testing.T) {
	assert := assert.New(t)
	list := types.CommaSeparatedList{}

	err := list.UnmarshalFlag("one,two")
	assert.Nil(err)
	assert.Equal(types.CommaSeparatedList{"one", "two"}, list, "should parse comma sepearated list")

	marshal, err := list.MarshalFlag()
	assert.Nil(err)
	assert.Equal("one,two", marshal, "should marshal back to comma sepearated list")
}

func TestConfigTrustedNetworks(t *testing.T) {
	assert := assert.New(t)

	c, err := NewConfig([]string{
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
