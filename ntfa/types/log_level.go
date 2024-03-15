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

func (l LogLevel) MarshalText() ([]byte, error) {
	s := l.String()
	if s == "" {
		return nil, fmt.Errorf("unkown log format: %d", l)
	}
	return []byte(s), nil
}

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

func (l *LogLevel) UnmarshalText(b []byte) error {
	return l.Set(string(b))
}

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
