package server

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

var idCounter atomic.Uint64

const idKey = "tfa-req-id"

type Middleware func(http.Handler) http.Handler

func Chain(xs ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		// next is the router
		// we prepend the middlewares here
		for i := len(xs) - 1; i >= 0; i-- {
			x := xs[i]
			next = x(next)
		}
		return next
	}
}

func (s *Server) Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// give each request an id
		id := idCounter.Add(1)
		idStr := strconv.FormatUint(id, 10)
		r.Header.Add(idKey, idStr)

		// all cookies into one string
		var sb strings.Builder
		for _, c := range r.Cookies() {
			sb.WriteString(c.String())
		}

		logger := s.logger.With(
			slog.String(idKey, r.Header.Get(idKey)),
			slog.Group("request",
				slog.String("method", r.Method),
				slog.String("proto", r.Proto),
				slog.String("host", r.Host),
				slog.String("url", r.URL.String()),
				slog.String("remote_addr", r.RemoteAddr),
			),
			slog.Group("forwarded",
				slog.String("method", escapeNewlines(r.Header.Get("X-Forwarded-Method"))),
				slog.String("proto", escapeNewlines(r.Header.Get("X-Forwarded-Proto"))),
				slog.String("host", escapeNewlines(r.Header.Get("X-Forwarded-Host"))),
				slog.String("uri", escapeNewlines(r.Header.Get("X-Forwarded-Uri"))),
				slog.String("source_ip", escapeNewlines(r.Header.Get("X-Forwarded-For"))),
			),
			slog.String("cookies", sb.String()),
		)

		if r.URL.Path == "/health" {
			// do not let healthcheck spam the logs
			logger.Debug("received request")
		} else {
			logger.Info("received request")
		}

		next.ServeHTTP(w, r)
	})
}

func RewriteRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Modify request
		r.Method = r.Header.Get("X-Forwarded-Method")
		r.Host = r.Header.Get("X-Forwarded-Host")

		// Read URI from header if we're acting as forward auth middleware
		if _, ok := r.Header["X-Forwarded-Uri"]; ok {
			r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
		}
		next.ServeHTTP(w, r)
	})
}
