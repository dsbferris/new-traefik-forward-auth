package appconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/thomseddon/go-flags"

	"github.com/dsbferris/new-traefik-forward-auth/provider"
	"github.com/dsbferris/new-traefik-forward-auth/types"
)

var config *AppConfig

// AppConfig holds the runtime application appconfig
type AppConfig struct {
	LogLevel  string `long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`
	LogFormat string `long:"log-format"  env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`

	AuthHost        types.Url            `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`
	Config          func(s string) error `long:"config" env:"CONFIG" description:"Path to appconfig file" json:"-"`
	CookieDomains   types.CookieDomains  `long:"cookie-domains" env:"COOKIE_DOMAIN" env-delim:"," description:"Comma separated list of Domains to set auth cookie on"`
	InsecureCookie  bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	CookieName      string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"Cookie Name"`
	CSRFCookieName  string               `long:"csrf-cookie-name" env:"CSRF_COOKIE_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	DefaultProvider string               `long:"default-provider" env:"DEFAULT_PROVIDER" default:"google" choice:"google" choice:"oidc" choice:"generic-oauth" description:"Default provider"`

	HeaderNames    types.CommaSeparatedList `long:"header-names" env:"HEADER_NAMES" default:"X-Forwarded-User" description:"User header names, comma separated"`
	LifetimeString int                      `long:"lifetime" env:"LIFETIME" default:"43200" description:"Lifetime in seconds"`
	Path           string                   `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	Secret         string                   `long:"secret" env:"SECRET" description:"Secret used for signing (required)" json:"-"`
	UserPath       string                   `long:"user-id-path" env:"USER_ID_PATH" default:"email" description:"Dot notation path of a UserID for use with whitelist and X-Forwarded-User"`

	Port int `long:"port" env:"PORT" default:"4181" description:"Port to listen on"`

	Providers provider.Providers `group:"providers" namespace:"providers" env-namespace:"PROVIDERS"`

	Domains   types.CommaSeparatedList `long:"domain" env:"DOMAIN" env-delim:"," description:"Only allow given email domains, comma separated, can be set multiple times"`
	Whitelist types.CommaSeparatedList `long:"whitelist" env:"WHITELIST" env-delim:"," description:"Only allow given UserID, comma separated, can be set multiple times"`
	// defaults to false
	MatchWhitelistOrDomain bool `long:"match-whitelist-or-domain" env:"MATCH_WHITELIST_OR_DOMAIN" description:"If true, allow users that match *either* whitelist or domain. If false and whitelist is set, allow only users from whitelist"`

	// Filled during transformations
	Lifetime time.Duration

	TrustedIPNetworks types.Networks `long:"trusted-ip-networks" env:"TRUSTED_IP_NETWORKS" env-delim:"," description:"Comma separated list of trusted IP addresses or IP networks (in CIDR notation) that are considered authenticated"`
}

// NewGlobalConfig creates a new global appconfig, parsed from command arguments
func NewGlobalConfig() *AppConfig {
	var err error
	config, err = NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	return config
}

// TODO: move appconfig parsing into new func "NewParsedConfig"

// NewConfig parses and validates provided configuration into a appconfig object
func NewConfig(args []string) (*AppConfig, error) {
	c := &AppConfig{}

	err := c.parseFlags(args)
	if err != nil {
		return c, err
	}

	// TODO: as log flags have now been parsed maybe we should return here so
	// any further errors can be logged via logrus instead of printed?

	// TODO: Rename "Validate" method to "Setup" and move all below logic

	// Transformations
	if len(c.Path) > 0 && c.Path[0] != '/' {
		c.Path = "/" + c.Path
	}
	c.Lifetime = time.Second * time.Duration(c.LifetimeString)

	return c, nil
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

// Validate validates a appconfig object
func (c *AppConfig) Validate(log *logrus.Logger) {
	// Check for show stopper errors
	if len(c.Secret) == 0 {
		log.Fatal("\"secret\" option must be set")
	}

	if len(c.HeaderNames) == 0 {
		log.Fatal("\"header-names\" option must be set")
	}

	// Setup default provider
	err := c.setupProvider(c.DefaultProvider)
	if err != nil {
		log.Fatal(err)
	}
	// TODO is more validation neccessary?
}

func (c AppConfig) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}

// GetProvider returns the provider of the given name
func (c *AppConfig) GetProvider(name string) (provider.Provider, error) {
	switch name {
	case "google":
		return &c.Providers.Google, nil
	case "oidc":
		return &c.Providers.OIDC, nil
	case "generic-oauth":
		return &c.Providers.GenericOAuth, nil
	}

	return nil, fmt.Errorf("Unknown provider: %s", name)
}

// GetConfiguredProvider returns the provider of the given name, if it has been
// configured. Returns an error if the provider is unknown, or hasn't been configured
func (c *AppConfig) GetConfiguredProvider(name string) (provider.Provider, error) {
	// Check the provider has been configured
	if !c.providerConfigured(name) {
		return nil, fmt.Errorf("Unconfigured provider: %s", name)
	}

	return c.GetProvider(name)
}

func (c *AppConfig) providerConfigured(name string) bool {
	return name == c.DefaultProvider
}

func (c *AppConfig) setupProvider(name string) error {
	// Check provider exists
	p, err := c.GetProvider(name)
	if err != nil {
		return err
	}

	// Setup
	if err := p.Setup(); err != nil {
		return err
	}

	return nil
}
