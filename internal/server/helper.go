package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dsbferris/new-traefik-forward-auth/internal/auth"
)

func escapeNewlines(data string) string {
	escapedData := strings.ReplaceAll(data, "\n", "")
	escapedData = strings.ReplaceAll(escapedData, "\r", "")
	return escapedData
}

func (s *Server) GetUserFromCookie(r *http.Request) (*string, error) {
	// Get auth cookie
	c, err := r.Cookie(s.config.Cookie.Name)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error getting cookie from request: %w", err)
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
