package types

import (
	"fmt"
	"log/slog"
	"strings"
)

type LogLevel slog.Level

const (
	DEBUG LogLevel = LogLevel(slog.LevelDebug)
	INFO  LogLevel = LogLevel(slog.LevelInfo)
	WARN  LogLevel = LogLevel(slog.LevelWarn)
	ERROR LogLevel = LogLevel(slog.LevelError)
)

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
	case DEBUG:
		return "debug"
	case INFO:
		return "info"
	case WARN:
		return "warn"
	case ERROR:
		return "error"
	}
	return ""
}

// implements [flag.Value]
func (l *LogLevel) Set(value string) error {
	switch strings.ToLower(value) {
	case "debug":
		*l = DEBUG
	case "info":
		*l = INFO
	case "warn":
		*l = WARN
	case "error":
		*l = ERROR
	default:
		return fmt.Errorf("unkown log format: %s", value)
	}
	return nil
}
