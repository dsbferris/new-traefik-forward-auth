package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dsbferris/new-traefik-forward-auth/auth"
)

func escapeNewlines(data string) string {
	escapedData := strings.ReplaceAll(data, "\n", "")
	escapedData = strings.ReplaceAll(escapedData, "\r", "")
	return escapedData
}

func (s *Server) GetUserFromCookie(r *http.Request) (*string, error) {
	// Get auth cookie
	c, err := r.Cookie(s.config.Cookie.Name)
	if err != nil {
		return nil, nil
	}
	// Validate cookie
	user, err := s.auth.ValidateCookie(r, c)
	if err != nil {
		if errors.Is(err, auth.ErrCookieExpired) {
			return nil, nil
		}
		if errors.Is(err, auth.ErrCookieInvalidSignature) {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid cookie: %w", err)
	}
	return &user, nil
}

// func (s *Server) requestLogger(r *http.Request, handler string, msg string) *slog.Logger {
// 	// Create logger
// 	var sb strings.Builder
// 	for _, c := range r.Cookies() {
// 		sb.WriteString(c.String())
// 	}

// 	logger := s.logger.WithGroup(msg).With(
// 		slog.String("handler", handler),
// 		slog.String("method", escapeNewlines(r.Header.Get("X-Forwarded-Method"))),
// 		slog.String("proto", escapeNewlines(r.Header.Get("X-Forwarded-Proto"))),
// 		slog.String("host", escapeNewlines(r.Header.Get("X-Forwarded-Host"))),
// 		slog.String("uri", escapeNewlines(r.Header.Get("X-Forwarded-Uri"))),
// 		slog.String("source_ip", escapeNewlines(r.Header.Get("X-Forwarded-For"))),
// 		slog.String("cookies", sb.String()),
// 	)
// 	return logger
// }
