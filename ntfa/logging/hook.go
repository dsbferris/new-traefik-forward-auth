package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/tidwall/gjson"
)

// Inspired by Logrus Testing Hook, this is my version for slog.
type Hook struct {
	buffer *bytes.Buffer
	logger *slog.Logger
}

func NewHookLogger(level slog.Level) (Hook, *slog.Logger) {
	return NewHookLoggerWithOptions(&slog.HandlerOptions{Level: level})
}

func NewHookLoggerWithOptions(options *slog.HandlerOptions) (Hook, *slog.Logger) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, options)
	logger := slog.New(handler)
	hook := Hook{
		buffer: &buf,
		logger: logger,
	}
	return hook, logger
}

func (h Hook) Logs() []Entry {
	split := bytes.Split(h.buffer.Bytes(), []byte("\n"))
	// the last element is a lot of times just an empty array.
	// this is due to how buffer allocates the capacity of the slice.
	// here we strip the last element if it is empty

	if len(split[len(split)-1]) == 0 {
		split = split[:len(split)-1]
	}
	entries := make([]Entry, len(split))
	for i, s := range split {
		json.Unmarshal(s, &entries[i])
		entries[i].Raw = s
	}
	return entries
}

// Clear the Hooks buffer, aka delete all Log Entries.
func (h Hook) Reset() {
	h.buffer.Reset()
}

// Entry is a convenience struct containing basic information
type Entry struct {
	Time    time.Time  `json:"time"`
	Level   slog.Level `json:"level"`
	Message string     `json:"msg"`
	Error   string     `json:"error"`
	Raw     json.RawMessage
}

// Use Get if you want to get a value from a LogEntry that is not contained within the message.
// Use the dot notation for that.
// For more information about dot notation see https://github.com/tidwall/gjson
func (e Entry) Get(path string) gjson.Result {
	return gjson.GetBytes(e.Raw, path)
}

// GetMany searches json for the multiple paths. The return value is a Result array where the number of items will be equal to the number of input paths.
// Use the dot notation for that.
// For more information about dot notation see https://github.com/tidwall/gjson
func (e Entry) GetMany(paths ...string) []gjson.Result {
	return gjson.GetManyBytes(e.Raw, paths...)
}
