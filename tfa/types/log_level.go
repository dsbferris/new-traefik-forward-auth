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
	var ls string
	switch l {
	case DEBUG:
		ls = "debug"
	case INFO:
		ls = "info"
	case WARN:
		ls = "warn"
	case ERROR:
		ls = "error"
	default:
		return nil, fmt.Errorf("unkown log format: %d", l)
	}
	return []byte(ls), nil
}

func (l LogLevel) String() string {
	b, _ := l.MarshalText()
	return string(b)
}

func (l *LogLevel) UnmarshalText(b []byte) error {
	ll := string(b)
	switch strings.ToLower(ll) {
	case "debug":
		*l = DEBUG
	case "info":
		*l = INFO
	case "warn":
		*l = WARN
	case "error":
		*l = ERROR
	default:
		return fmt.Errorf("unkown log format: %s", ll)
	}
	return nil
}
