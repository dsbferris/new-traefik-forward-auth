package appconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dsbferris/new-traefik-forward-auth/provider"
	"github.com/dsbferris/new-traefik-forward-auth/types"
	"github.com/thomseddon/go-flags"
)

var (
	ErrSecretEmpty      = errors.New("secret must be set")
	ErrHeaderNamesEmpty = errors.New("header-names must be set")
	ErrInvalidPath      = errors.New("path must start with a /")
	ErrMultipleProvider = errors.New("do not setup multiple providers")
	ErrNoProvider       = errors.New("no provider set")
)

// AppConfig holds the runtime application appconfig
type AppConfig struct {
	LogLevel  types.LogLevel  `long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"debug" choice:"info" choice:"warn" choice:"error" description:"Log level"`
	LogFormat types.LogFormat `long:"log-format"  env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`

	AuthHost       types.Url            `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`
	Config         func(s string) error `long:"config" env:"CONFIG" description:"Path to appconfig file" json:"-"`
	CookieDomains  types.CookieDomains  `long:"cookie-domains" env:"COOKIE_DOMAIN" env-delim:"," description:"Comma separated list of Domains to set auth cookie on"`
	InsecureCookie bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	CookieName     string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"Cookie Name"`
	CSRFCookieName string               `long:"csrf-cookie-name" env:"CSRF_COOKIE_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`

	HeaderNames types.CommaSeparatedList `long:"header-names" env:"HEADER_NAMES" default:"X-Forwarded-User" description:"User header names, comma separated"`
	Path        string                   `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	Secret      string                   `long:"secret" env:"SECRET" description:"Secret used for signing (required)" json:"-"`
	UserPath    string                   `long:"user-id-path" env:"USER_ID_PATH" default:"email" description:"Dot notation path of a UserID for use with whitelist and X-Forwarded-User"`

	Port int `long:"port" env:"PORT" default:"4181" description:"Port to listen on"`

	Providers        provider.Providers `group:"providers" namespace:"providers" env-namespace:"PROVIDERS"`
	SelectedProvider provider.Provider

	Domains   types.CommaSeparatedList `long:"domain" env:"DOMAIN" env-delim:"," description:"Only allow given email domains, comma separated, can be set multiple times"`
	Whitelist types.CommaSeparatedList `long:"whitelist" env:"WHITELIST" env-delim:"," description:"Only allow given UserID, comma separated, can be set multiple times"`
	// defaults to false
	MatchWhitelistOrDomain bool `long:"match-whitelist-or-domain" env:"MATCH_WHITELIST_OR_DOMAIN" description:"If true, allow users that match *either* whitelist or domain. If false and whitelist is set, allow only users from whitelist"`

	// Filled during transformations
	Lifetime time.Duration `long:"lifetime" env:"LIFETIME" default:"12h" description:"Forward Auth Cookie Lifetime. See time.ParseDuration() for valid values."`

	TrustedIPNetworks types.Networks `long:"trusted-ip-networks" env:"TRUSTED_IP_NETWORKS" env-delim:"," description:"Comma separated list of trusted IP addresses or IP networks (in CIDR notation) that are considered authenticated"`
}

// NewDefaultConfig creates a new global appconfig, parsed from command arguments
func NewDefaultConfig() (*AppConfig, error) {
	return NewConfig(os.Args[1:])
}

// NewConfig parses and validates provided configuration into a appconfig object
func NewConfig(args []string) (*AppConfig, error) {
	config := &AppConfig{}

	err := config.parseFlags(args)
	if err != nil {
		return config, err
	}

	// Check for show stopper errors
	if !strings.HasPrefix(config.Path, "/") {
		return nil, ErrInvalidPath
	}
	if len(config.Secret) == 0 || strings.TrimSpace(config.Secret) == "" {
		return nil, ErrSecretEmpty
	}

	if len(config.HeaderNames) == 0 {
		return nil, ErrHeaderNamesEmpty
	}
	for _, h := range config.HeaderNames {
		if strings.TrimSpace(h) == "" {
			return nil, ErrHeaderNamesEmpty
		}
	}

	// auto detect a configured provider
	gotProvider := false
	for _, p := range config.Providers.GetAll() {
		err := p.Setup()
		if err == nil {
			if gotProvider {
				return nil, ErrMultipleProvider
			}
			gotProvider = true
			config.SelectedProvider = p
		}
	}
	if !gotProvider {
		return nil, ErrNoProvider
	}

	// TODO is more validation neccessary?

	return config, nil
}

func (c *AppConfig) parseFlags(args []string) error {
	p := flags.NewParser(c, flags.Default|flags.IniUnknownOptionHandler)
	p.UnknownOptionHandler = c.parseUnknownFlag

	i := flags.NewIniParser(p)
	c.Config = func(s string) error {
		// Try parsing at as an ini
		return i.ParseFile(s)
	}

	_, err := p.ParseArgs(args)
	if err != nil {
		return handleFlagError(err)
	}

	return nil
}

func (c *AppConfig) parseUnknownFlag(option string, arg flags.SplitArgument, args []string) ([]string, error) {
	return args, fmt.Errorf("unknown flag: %v", option)
}

func handleFlagError(err error) error {
	flagsErr, ok := err.(*flags.Error)
	if ok && flagsErr.Type == flags.ErrHelp {
		// Library has just printed cli help
		os.Exit(0)
	}
	return err
}

func (c AppConfig) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}
