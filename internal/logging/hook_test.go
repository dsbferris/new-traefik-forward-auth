package logging_test

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/dsbferris/new-traefik-forward-auth/logging"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func TestHook(t *testing.T) {
	assert := assert.New(t)

	t.Run("test basic", func(t *testing.T) {
		msg := "debug msg"
		hook, logger := logging.NewHookLogger(slog.LevelDebug)
		start := time.Now()
		logger.Debug(msg)
		stop := time.Now()

		logs := hook.Logs()
		assert.Len(logs, 1)

		log := logs[0]
		assert.Equal(msg, log.Message)
		assert.Equal(slog.LevelDebug, log.Level)
		assert.GreaterOrEqual(log.Time, start)
		assert.LessOrEqual(log.Time, stop)
		assert.Empty(log.Error)
		assert.NotEmpty(log.Raw)
	})

	t.Run("test level and order", func(t *testing.T) {
		hook, logger := logging.NewHookLogger(slog.LevelDebug)
		logger.Debug("debug msg")
		logger.Info("info msg")
		logger.Warn("warn msg")
		logger.Error("error msg")
		logs := hook.Logs()
		assert.Len(logs, 4)
		assert.Equal(slog.LevelDebug, logs[0].Level)
		assert.Equal(slog.LevelInfo, logs[1].Level)
		assert.Equal(slog.LevelWarn, logs[2].Level)
		assert.Equal(slog.LevelError, logs[3].Level)
	})

	t.Run("test lower levels", func(t *testing.T) {
		hook, logger := logging.NewHookLogger(slog.LevelInfo)
		logger.Debug("debug msg")
		logs := hook.Logs()
		assert.Len(logs, 0, "logs should not contains messages of lower levels")
	})

	t.Run("test error", func(t *testing.T) {
		hook, logger := logging.NewHookLogger(slog.LevelInfo)
		err := errors.New("bad")
		logger.Error("something bad happened", slog.String("error", err.Error()))
		logs := hook.Logs()
		assert.Len(logs, 1)
		log := logs[0]
		assert.Equal(err.Error(), log.Error)
	})

	t.Run("test reset", func(t *testing.T) {
		hook, logger := logging.NewHookLogger(slog.LevelInfo)
		logger.Info("msg1")
		logs := hook.Logs()
		assert.Len(logs, 1)

		hook.Reset()
		logs = hook.Logs()
		assert.Len(logs, 0)
	})

	t.Run("test get", func(t *testing.T) {
		hook, logger := logging.NewHookLogger(slog.LevelInfo)
		i := int(12)
		i64 := int64(34)
		logger.Info("msg1", slog.Int("int", i), slog.Int64("int64", i64))
		logs := hook.Logs()
		assert.Len(logs, 1)
		var r gjson.Result
		r = logs[0].Get("int")
		assert.Equal(i, int(r.Int()))
		r = logs[0].Get("int64")
		assert.Equal(i64, r.Int())
	})

	t.Run("test get many", func(t *testing.T) {
		hook, logger := logging.NewHookLogger(slog.LevelInfo)
		i := int(12)
		i64 := int64(34)
		logger.Info("msg1", slog.Int("int", i), slog.Int64("int64", i64))
		logs := hook.Logs()
		assert.Len(logs, 1)
		results := logs[0].GetMany("int", "int64")
		assert.Len(results, 2)
		assert.Equal(int(results[0].Int()), i)
		assert.Equal(results[1].Int(), i64)
	})

	t.Run("test get nested", func(t *testing.T) {
		hook, logger := logging.NewHookLogger(slog.LevelInfo)
		logger.Info("msg1", slog.Group("grp1", slog.String("key", "value")))
		logs := hook.Logs()
		assert.Len(logs, 1)
		r := logs[0].Get("grp1.key")
		assert.Equal(r.String(), "value")
	})

}
