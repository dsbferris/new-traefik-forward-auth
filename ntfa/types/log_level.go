package types

import (
	"fmt"
	"log/slog"
	"strings"
)

type LogLevel slog.Level

const (
	LEVEL_DEBUG LogLevel = LogLevel(slog.LevelDebug)
	LEVEL_INFO  LogLevel = LogLevel(slog.LevelInfo)
	LEVEL_WARN  LogLevel = LogLevel(slog.LevelWarn)
	LEVEL_ERROR LogLevel = LogLevel(slog.LevelError)
)

// UnmarshalFlag converts a string to a CookieDomain
func (l *LogLevel) UnmarshalFlag(value string) error {
	return l.Set(value)
}

// MarshalFlag converts a CookieDomain to a string
func (l *LogLevel) MarshalFlag() (string, error) {
	return l.String(), nil
}

// implements [encoding.TextMarshaler]
func (l LogLevel) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

// implements [encoding.TextUnmarshaler]
func (l *LogLevel) UnmarshalText(b []byte) error {
	return l.Set(string(b))
}

// implements [flag.Value]
func (l LogLevel) String() string {
	switch l {
	case LEVEL_DEBUG:
		return "debug"
	case LEVEL_INFO:
		return "info"
	case LEVEL_WARN:
		return "warn"
	case LEVEL_ERROR:
		return "error"
	}
	return ""
}

// implements [flag.Value]
func (l *LogLevel) Set(value string) error {
	switch strings.ToLower(value) {
	case "debug":
		*l = LEVEL_DEBUG
	case "info":
		*l = LEVEL_INFO
	case "warn":
		*l = LEVEL_WARN
	case "error":
		*l = LEVEL_ERROR
	default:
		return fmt.Errorf("unkown log format: %s", value)
	}
	return nil
}
