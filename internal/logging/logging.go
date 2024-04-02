package logging

import (
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/dsbferris/new-traefik-forward-auth/types"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
)

func NewLogger(format types.LogFormat, level types.LogLevel) (*slog.Logger, error) {
	var log *slog.Logger

	switch format {
	case types.FORMAT_PRETTY:
		log = getPrettyLogger(level)
	case types.FORMAT_TEXT:
		log = getTextLogger(level)
	case types.FORMAT_JSON:
		log = getJsonLogger(level)
	default:
		return nil, fmt.Errorf("unkown log format: %d", format)
	}

	log.Debug("PID: " + strconv.Itoa(os.Getpid()))

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		log.Debug("call to debug.ReadBuildInfo() failed")
	} else {
		log.Debug("go version: " + buildInfo.GoVersion)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Debug("call to os.Getwd() failed")
	} else {
		log.Debug("current working directoy: " + cwd)
	}
	return log, nil
}

func getPrettyLogger(level types.LogLevel) *slog.Logger {
	w := os.Stderr
	opts := &tint.Options{
		TimeFormat: time.RFC3339,
		Level:      slog.Level(level),
		//isatty checks if current terminal supports colors
		NoColor:   !isatty.IsTerminal(w.Fd()),
		AddSource: true,
	}
	// tint allows for nice colorized output
	// colorable adds support for windows
	return slog.New(tint.NewHandler(colorable.NewColorable(w), opts))
}

func getTextLogger(level types.LogLevel) *slog.Logger {
	w := os.Stderr
	opts := &tint.Options{
		TimeFormat: time.RFC3339,
		Level:      slog.Level(level),
		NoColor:    true,
		AddSource:  true,
	}
	return slog.New(tint.NewHandler(w, opts))
}

func getJsonLogger(level types.LogLevel) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.Level(level),
	}))
}
