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
	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
)

var (
	ErrSecretEmpty      = errors.New("secret must be set")
	ErrHeaderNamesEmpty = errors.New("header-names must be set")
	ErrInvalidPath      = errors.New("path must start with a /")
	ErrMultipleProvider = errors.New("do not setup multiple providers")
	ErrNoProvider       = errors.New("no provider set")
)

type LogConfig struct {
	Verbose bool            `short:"v" long:"verbose" env:"VERBOSE" description:"Short hand for log level debug. Will override any setting for level"`
	Level   types.LogLevel  `short:"l" long:"level" env:"LEVEL" default:"warn" choice:"debug" choice:"info" choice:"warn" choice:"error" description:"Log level"`
	Format  types.LogFormat `short:"f" long:"format" env:"FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`
}

type WhitelistConfig struct {
	Domains []string `long:"domains" env:"DOMAINS" env-delim:"," description:"Only allow given email domains, can be set multiple times, ONLY comma separated as ENV"`
	Users   []string `long:"users" env:"USERS" env-delim:"," description:"Only allow given Users, can be set multiple times, ONLY comma separated as ENV"`
	// defaults to false
	MatchUserOrDomain bool `long:"match-user-or-domain" env:"MATCH_USER_OR_DOMAIN" description:"If true, allow users that match *either* users or domains whitelist. If false and users whitelist is set, allow only users from users whitelist"`

	Networks types.Networks `long:"networks" env:"NETWORKS" env-delim:"," description:"List of trusted IP addresses or IP networks (in CIDR notation) that are considered authenticated, comma separated or set multiple times"`
}

type CookieConfig struct {
	Domains  types.CookieDomains `long:"domains" env:"DOMAINS" env-delim:"," description:"List of Domains to set auth cookie on, comma separated or set multiple times"`
	Insecure bool                `long:"insecure" env:"INSECURE" description:"Use insecure cookies"`
	Name     string              `long:"name" env:"NAME" default:"_forward_auth" description:"Cookie Name"`
	CSRFName string              `long:"csrf-name" env:"CSRF_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	Lifetime time.Duration       `long:"lifetime" env:"LIFETIME" default:"12h" description:"Forward Auth Cookie Lifetime. See time.ParseDuration() for valid values."`
}

// AppConfig holds the runtime application appconfig
type AppConfig struct {
	Config  func(s string) error `short:"c" long:"config" env:"CONFIG" description:"Path to appconfig file" json:"-"`
	EnvFile func(s string) error `short:"e" long:"env-file" description:"Path to env file" json:"-"`

	Log LogConfig `group:"Log Options" namespace:"log" env-namespace:"LOG"`

	Port     int    `long:"port" env:"PORT" default:"4181" description:"Port to listen on"`
	AuthHost string `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`

	HeaderNames []string `long:"header-names" env:"HEADER_NAMES" default:"X-Forwarded-User" description:"User header names, can be set multiple times, ONLY comma separated as ENV"`
	UrlPath     string   `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	Secret      string   `long:"secret" env:"SECRET" description:"Secret used for signing (required)" json:"-"`
	UserPath    string   `long:"user-id-path" env:"USER_ID_PATH" default:"email" description:"Dot notation path of a UserID for use with whitelist and X-Forwarded-User"`

	Cookie    CookieConfig    `group:"Cookie Options" namespace:"cookie" env-namespace:"COOKIE"`
	Whitelist WhitelistConfig `group:"Whitelist Options" namespace:"whitelist" env-namespace:"WHITELIST"`

	Providers provider.Providers `group:"providers" namespace:"providers" env-namespace:"PROVIDERS"`

	SelectedProvider provider.Provider
}

// NewDefaultConfig creates a new global appconfig, parsed from command arguments
func NewDefaultConfig() (*AppConfig, error) {
	return NewConfig(os.Args[1:])
}

// NewConfig parses and validates provided configuration into a appconfig object
func NewConfig(args []string) (*AppConfig, error) {
	config := &AppConfig{}

	err := config.parseFlags(args)
	return config, err
}

func (config *AppConfig) parseFlags(args []string) error {
	p := flags.NewParser(config, flags.Default)
	// return error on unkown flags
	p.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		return args, fmt.Errorf("unknown flag: %v", option)
	}
	// if config flag is set, execute ini parsing
	config.Config = func(s string) error {
		i := flags.NewIniParser(p)
		return i.ParseFile(s)
	}
	// if env file flag is set, execute load env variables
	config.EnvFile = func(s string) error {
		return godotenv.Load(s)
	}
	_, err := p.ParseArgs(args)

	// on help print, exit with 0
	if flags.WroteHelp(err) {
		os.Exit(0)
	}
	return err
}

func (config *AppConfig) Validate() error {

	if config.Log.Verbose {
		config.Log.Level = types.LEVEL_DEBUG
	}

	// Check for show stopper errors
	// TODO URL PATH MUST NOT BE JUST /
	if !strings.HasPrefix(config.UrlPath, "/") {
		return ErrInvalidPath
	}
	if len(config.Secret) == 0 || strings.TrimSpace(config.Secret) == "" {
		return ErrSecretEmpty
	}

	if len(config.HeaderNames) == 0 {
		return ErrHeaderNamesEmpty
	}
	for _, h := range config.HeaderNames {
		if strings.TrimSpace(h) == "" {
			return ErrHeaderNamesEmpty
		}
	}
	// TODO valdidate auth host can be parsed into url
	//url, err := url.Parse(value)

	// auto detect a configured provider
	gotProvider := false
	for _, p := range config.Providers.GetAll() {
		err := p.Setup()
		if err == nil {
			if gotProvider {
				return ErrMultipleProvider
			}
			gotProvider = true
			config.SelectedProvider = p
		}
	}
	if !gotProvider {
		return ErrNoProvider
	}

	// TODO is more validation neccessary?

	return nil
}

func (config AppConfig) String() string {
	jsonConf, _ := json.Marshal(config)
	return string(jsonConf)
}
