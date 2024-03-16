package logging_test

import (
	"log/slog"
	"testing"

	"github.com/dsbferris/new-traefik-forward-auth/logging"
	"github.com/stretchr/testify/assert"
)

func TestHook(t *testing.T) {
	assert := assert.New(t)

	t.Run("basic", func(t *testing.T) {
		hook, logger := logging.NewHookLogger(&slog.HandlerOptions{Level: slog.LevelDebug})
		logger.Debug("debug msg")
		logs := hook.Logs()
		assert.Len(logs, 1, "there should be one log entry")
		log := logs.Get(0)
		msg := log.Get(logging.MESSAGE).String()
		assert.Equal(msg, "debug msg")
	})

	// logger.Debug("debug msg2", slog.String("str", "value"))
	// logger.Debug("debug msg3", slog.Int("int", 1234))
	// logger.Debug("debug msg4", slog.Group("grp", slog.String("grp1", "v1")))
	// fullBuffer := hook.buffer.Bytes()
	// partsBuffer := bytes.Split(fullBuffer, []byte("\n"))
	// for _, partBytes := range partsBuffer {
	// 	part := string(partBytes)
	// 	fmt.Println(part)
	// }
}
