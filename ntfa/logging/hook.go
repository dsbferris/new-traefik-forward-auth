package logging

import (
	"bytes"
	"log/slog"

	"github.com/tidwall/gjson"
)

const (
	MESSAGE = "msg"
	LEVEL   = "level"
)

type Hook struct {
	buffer *bytes.Buffer
	logger *slog.Logger
}

func NewHookLogger(options *slog.HandlerOptions) (Hook, *slog.Logger) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, options)
	logger := slog.New(handler)
	hook := Hook{
		buffer: &buf,
		logger: logger,
	}
	return hook, logger
}

// Returns chronologically sorted array of []byte of the json messages.
func (h Hook) Logs() LogEntries {
	split := bytes.Split(h.buffer.Bytes(), []byte("\n"))
	// the last element is a lot of times just an empty array.
	// this is due to how buffer allocates the capacity of the slice.
	// here we strip the last element if it is empty
	sl := len(split)
	if len(split[sl-1]) == 0 {
		split = split[:sl-1]
	}
	return LogEntries(split)
}

// Clear the Hooks buffer, aka delete all Log Entries.
func (h Hook) Reset() {
	h.buffer.Reset()
}

type LogEntries [][]byte

func (l LogEntries) Get(index int) LogEntry {
	return l[index]
}

type LogEntry []byte

func (l LogEntry) Get(path string) gjson.Result {
	return gjson.GetBytes(l, path)
}

func (l LogEntry) GetMany(paths ...string) []gjson.Result {
	return gjson.GetManyBytes(l, paths...)
}
