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

	assert.Equal(types.LEVEL_WARN, config.Log.Level)
	assert.Equal(types.FORMAT_TEXT, config.Log.Format)

	assert.Equal("", config.AuthHost)
	assert.Len(config.Cookie.Domains, 0)
	assert.False(config.Cookie.Insecure)
	assert.Equal("_forward_auth", config.Cookie.Name)
	assert.Equal("_forward_auth_csrf", config.Cookie.CSRFName)
	assert.Equal(&config.Providers.Google, config.SelectedProvider)
	assert.Len(config.Whitelist.Domains, 0)
	assert.Equal([]string{"X-Forwarded-User"}, config.HeaderNames)
	assert.Equal(time.Second*time.Duration(43200), config.Cookie.Lifetime)
	assert.False(config.Whitelist.MatchUserOrDomain)
	assert.Equal("/_oauth", config.UrlPath)
	assert.Len(config.Whitelist.Users, 0)
	assert.Equal(config.Port, 4181)

	assert.Equal("select_account", config.Providers.Google.Prompt)

	assert.Len(config.Whitelist.Networks, 0)
}

func TestConfigParseArgs(t *testing.T) {
	assert := assert.New(t)
	config, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.oidc.client-id=id",
		"--providers.oidc.client-secret=secret",
		"--providers.oidc.issuer-url=https://accounts.google.com",

		"--port=8000",
		"--cookie.name=cookiename",
		"--cookie.csrf-name", "csrfcookiename",
		"--cookie.lifetime=200s",
		"-v",
		"-l", "error",
	})
	assert.Nil(err)
	assert.Equal(types.LEVEL_ERROR, config.Log.Level)
	assert.Equal(true, config.Log.Verbose)

	err = config.Validate()
	assert.Nil(err)

	// Check normal flags
	assert.Equal(types.LEVEL_DEBUG, config.Log.Level, "should replace log level when verbose is set")
	assert.Equal("cookiename", config.Cookie.Name)
	assert.Equal("csrfcookiename", config.Cookie.CSRFName)
	assert.Equal(&config.Providers.OIDC, config.SelectedProvider)
	assert.Equal(8000, config.Port)
	assert.Equal(time.Second*time.Duration(200), config.Cookie.Lifetime, "lifetime should be read and converted to duration")
}

func TestConfigParseUnknownFlags(t *testing.T) {
	_, err := NewConfig([]string{
		"--unknown=_oauthpath2",
	})

	if assert.Error(t, err) {
		assert.Equal(t, "unknown flag: unknown", err.Error())
	}
}

func TestConfigSetMultipleTimes(t *testing.T) {
	assert := assert.New(t)
	config, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",

		"--whitelist.domains=test@test.com",
		"--whitelist.domains=test2@test2.com",
	})
	require.Nil(t, err)

	expected1 := []string{"test@test.com", "test2@test2.com"}
	assert.Equal(expected1, config.Whitelist.Domains, "should read whitelist when specified multiple times")
}

func TestConfigParseIni(t *testing.T) {
	assert := assert.New(t)
	configFile1, _ := filepath.Abs("../testfiles/config0")
	configFile2, _ := filepath.Abs("../testfiles/config1")
	config, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",

		"--config=" + configFile1,
		"--config=" + configFile2,
		"--cookie.csrf-name=csrfcookiename",
	})
	require.Nil(t, err)

	assert.Equal("inicookiename", config.Cookie.Name, "should be read from ini file")
	assert.Equal("csrfcookiename", config.Cookie.CSRFName, "should be read from ini file")
	assert.Equal("/two", config.UrlPath, "variable in second ini file should override first ini file")
}

func TestConfigParseEnvironment(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("PROVIDERS_GOOGLE_CLIENT_ID", "env_client_id")
	os.Setenv("COOKIE_NAME", "env_cookie_name")
	os.Setenv("COOKIE_DOMAINS", "test1.com,example.org")
	os.Setenv("WHITELIST_DOMAINS", "test2.com,example.org")
	os.Setenv("WHITELIST_USERS", "test3.com,example.org")

	config, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-secret=secret",
	})
	assert.Nil(err)

	assert.Equal("env_cookie_name", config.Cookie.Name, "variable should be read from environment")
	assert.Equal("env_client_id", config.Providers.Google.ClientID, "namespace variable should be read from environment")
	assert.Equal(types.CookieDomains{
		types.NewCookieDomain("test1.com"),
		types.NewCookieDomain("example.org"),
	}, config.Cookie.Domains, "array variable should be read from environment COOKIE_DOMAIN")
	assert.Equal([]string{"test2.com", "example.org"}, config.Whitelist.Domains, "array variable should be read from environment DOMAIN")
	assert.Equal([]string{"test3.com", "example.org"}, config.Whitelist.Users, "array variable should be read from environment WHITELIST")

	os.Unsetenv("PROVIDERS_GOOGLE_CLIENT_ID")
	os.Unsetenv("COOKIE_NAME")
	os.Unsetenv("COOKIE_DOMAINS")
	os.Unsetenv("WHITELIST_DOMAINS")
	os.Unsetenv("WHITELIST_USERS")
}

func TestConfigParseEnvFile(t *testing.T) {
	assert := assert.New(t)

	envFile, _ := filepath.Abs("../testfiles/env.sh")
	config, err := NewConfig([]string{
		"-e", envFile,
	})
	assert.Nil(err)

	assert.Equal("env_cookie_name", config.Cookie.Name, "variable should be read from environment")
	assert.Equal("env_client_id", config.Providers.Google.ClientID, "namespace variable should be read from environment")
	assert.Equal(types.CookieDomains{
		types.NewCookieDomain("test1.com"),
		types.NewCookieDomain("example.org"),
	}, config.Cookie.Domains, "array variable should be read from environment COOKIE_DOMAIN")
	assert.Equal([]string{"test2.com", "example.org"}, config.Whitelist.Domains, "array variable should be read from environment DOMAIN")
	assert.Equal([]string{"test3.com", "example.org"}, config.Whitelist.Users, "array variable should be read from environment WHITELIST")

}

func TestConfigTrustedNetworks(t *testing.T) {
	assert := assert.New(t)

	config, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",

		"--whitelist.networks=1.2.3.4,30.1.0.0/16",
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
		got, err := config.Whitelist.Networks.ConatainsIp(in)
		assert.NoError(err)
		assert.Equal(want, got, "ip address: %s", in)
	}

}

func TestConfigTrustedNetworks2(t *testing.T) {
	assert := assert.New(t)

	config, err := NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",

		"--whitelist.networks=1.2.3.4",
		"--whitelist.networks=30.1.0.0/16",
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
		got, err := config.Whitelist.Networks.ConatainsIp(in)
		assert.NoError(err)
		assert.Equal(want, got, "ip address: %s", in)
	}

}
