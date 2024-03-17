package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/dsbferris/new-traefik-forward-auth/appconfig"
	"github.com/dsbferris/new-traefik-forward-auth/auth"
)

// Server contains router and handler methods
type Server struct {
	muxer  *http.ServeMux
	logger *slog.Logger
	config *appconfig.AppConfig
	auth   *auth.Auth
}

// NewServer creates a new server object and builds router
func NewServer(logger *slog.Logger, config *appconfig.AppConfig) *Server {
	s := &Server{
		logger: logger,
		config: config,
		auth:   auth.NewAuth(config),
	}
	s.buildRoutes()
	return s
}

func (s *Server) escapeNewlines(data string) string {
	escapedData := strings.ReplaceAll(data, "\n", "")
	escapedData = strings.ReplaceAll(escapedData, "\r", "")
	return escapedData
}

func (s *Server) buildRoutes() {
	s.muxer = http.NewServeMux()

	// Add callback handler
	s.muxer.HandleFunc(s.config.Path, s.AuthCallbackHandler)

	// Add login / logout handler
	s.muxer.HandleFunc(s.config.Path+"/login", s.LoginHandler)
	s.muxer.HandleFunc(s.config.Path+"/logout", s.LogoutHandler)

	// Add health check handler
	s.muxer.Handle("/healthz", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))

	// Add a default handler
	s.muxer.HandleFunc("/", s.authHandler)
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Pass to mux
	s.muxer.ServeHTTP(w, r)
}

func (s *Server) GetUserFromCookie(r *http.Request) (*string, error) {
	// Get auth cookie
	c, err := r.Cookie(s.config.CookieName)
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

func (s *Server) authHandler(w http.ResponseWriter, r *http.Request) {

	logger := s.requestLogger(r, "Auth", "Authenticating request")

	unauthorized := func(w http.ResponseWriter) {
		http.Error(w, "Unauthorized", 401)
	}

	ipAddr := s.escapeNewlines(r.Header.Get("X-Forwarded-For"))
	if ipAddr == "" {
		logger.Warn("missing x-forwarded-for header")
	} else {
		ok, err := s.config.TrustedIPNetworks.ConatainsIp(ipAddr)
		if err != nil {
			logger.Warn("invalid forwarded for", slog.String("error", err.Error()))
		} else if ok {
			logger.Info("authenticated remote address", slog.String("addr", ipAddr))
			w.WriteHeader(200)
			return
		}
	}

	// Get user from cookie
	user, err := s.GetUserFromCookie(r)
	if err != nil {
		logger.Warn("invalid user", slog.String("error", err.Error()))
		unauthorized(w)
		return
	}
	if user == nil {
		s.authRedirect(logger, w, r, s.auth.CurrentUrl(r), false)
		return
	}

	// Validate user
	valid := s.auth.ValidateUser(*user)
	if !valid {
		logger.Warn("invalid user", slog.String("user", s.escapeNewlines(*user)))
		unauthorized(w)
		return
	}

	// Valid request
	logger.Debug("Allowing valid request")
	for _, headerName := range s.config.HeaderNames {
		w.Header().Set(headerName, *user)
	}
	w.WriteHeader(200)
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler(w http.ResponseWriter, r *http.Request) {

	// Logging setup
	logger := s.requestLogger(r, "AuthCallback", "Handling callback")

	// Check state
	state := s.escapeNewlines(r.URL.Query().Get("state"))
	err := s.auth.ValidateState(state)
	if err != nil {
		logger.Warn("error validating state", slog.String("error", err.Error()))
		http.Error(w, "Not authorized", 401)
		return
	}

	// Check for CSRF cookie
	c, err := s.auth.FindCSRFCookie(r, state)
	if err != nil {
		logger.Info("Missing csrf cookie")
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate CSRF cookie against state
	valid, providerName, redirect, err := s.auth.ValidateCSRFCookie(c, state)
	if !valid {
		logger.Warn("error validating csrf cookie", slog.String("error", err.Error()), slog.String("csrf_cookie", c.String()))
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate provider
	p := s.config.SelectedProvider
	if p.Name() != providerName {
		logger.Warn("invalid provider in csrf cookie",
			slog.String("selected_provider", p.Name()),
			slog.String("csrf_provider", providerName),
			slog.String("csrf_cookie", c.String()),
		)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Clear CSRF cookie
	http.SetCookie(w, s.auth.ClearCSRFCookie(r, c))

	// Validate redirect
	redirectURL, err := s.auth.ValidateRedirect(r, redirect)
	if err != nil {
		logger.Warn("invalid redirect in csrf", slog.String("error", err.Error()), slog.String("received_redirect", redirect))
		http.Error(w, "Not authorized", 401)
		return
	}

	// Check error
	authError := r.URL.Query().Get("error")
	if authError == "login_required" || authError == "consent_required" {
		// Retry with without prompt (none) parameter
		s.authRedirect(logger, w, r, redirect, true)
		return
	}

	// Exchange code for token
	redirectUri := s.auth.RedirectUri(r)
	code := r.URL.Query().Get("code")
	token, err := p.ExchangeCode(redirectUri, code)
	if err != nil {
		logger.Error("Code exchange failed with provider", slog.String("error", err.Error()))
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Get user
	user, err := p.GetUser(token, s.config.UserPath)
	if err != nil {
		logger.Error("Error getting user", slog.String("error", err.Error()))
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Generate cookie
	http.SetCookie(w, s.auth.MakeCookie(r, user))
	slog.Info("successfully generated auth cookie, redirecting user",
		slog.String("provider", providerName),
		slog.String("redirect", redirect),
		slog.String("user", user),
	)

	// Redirect
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)

}

// LoginHandler logs a user in
func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {

	logger := s.requestLogger(r, "Login", "Handling login")
	logger.Info("Explicit user login")

	// Calculate and validate redirect
	redirect := s.auth.GetRedirectURI(r)
	redirectURL, err := s.auth.ValidateLoginRedirect(r, redirect)
	if err != nil {
		logger.Warn("invalid redirect in login", slog.String("error", err.Error()), slog.String("received_redirect", redirect))
		http.Error(w, "Invalid redirect: "+err.Error(), 400)
		return
	}

	// Get user
	user, err := s.GetUserFromCookie(r)
	if err != nil {
		logger.Warn("invalid user", slog.String("error", err.Error()))
		http.Error(w, "Invalid cookie", 400)
		return
	}
	if user != nil { // Already logged in
		if redirectURL != nil {
			http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
			return
		} else {
			w.WriteHeader(200)
			return
		}
	}

	// Login
	s.authRedirect(logger, w, r, redirectURL.String(), false)

}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler(w http.ResponseWriter, r *http.Request) {

	logger := s.requestLogger(r, "Logout", "Handling logout")
	logger.Info("Logged out user")

	// Clear cookie
	http.SetCookie(w, s.auth.ClearCookie(r))

	// Calculate and validate redirect
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	redirectURL, err := s.auth.ValidateLoginRedirect(r, redirect)
	if err != nil {
		logger.Warn("invalid redirect in login", slog.String("error", err.Error()), slog.String("received_redirect", redirect))
		http.Error(w, "Invalid redirect: "+err.Error(), 400)
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)

}

func (s *Server) authRedirect(logger *slog.Logger, w http.ResponseWriter, r *http.Request, returnUrl string, forcePrompt bool) {
	// Error indicates no cookie, generate nonce
	nonce, err := s.auth.Nonce()
	if err != nil {
		logger.Error("error generating nonce", slog.String("error", err.Error()))
		http.Error(w, "Service unavailable", 503)
		return
	}

	// clean existing CSRF cookie
	for _, v := range r.Cookies() {
		if strings.Contains(v.Name, s.config.CSRFCookieName) {
			http.SetCookie(w, s.auth.ClearCSRFCookie(r, v))
		}
	}
	// Set the CSRF cookie
	csrf := s.auth.MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !s.config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	p := s.config.SelectedProvider
	loginURL := p.GetLoginURL(s.auth.RedirectUri(r), s.auth.MakeState(returnUrl, p, nonce), forcePrompt)
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.Debug("set CSRF cookie and redirected to provider login url", slog.String("csrf_cookie", csrf.String()), slog.String("login_url", loginURL))
}

func (s *Server) requestLogger(r *http.Request, handler string, msg string) *slog.Logger {
	// Create logger

	var sb strings.Builder
	for _, c := range r.Cookies() {
		sb.WriteString(c.String())
	}

	logger := s.logger.WithGroup(msg).With(
		slog.String("handler", handler),
		slog.String("method", s.escapeNewlines(r.Header.Get("X-Forwarded-Method"))),
		slog.String("proto", s.escapeNewlines(r.Header.Get("X-Forwarded-Proto"))),
		slog.String("host", s.escapeNewlines(r.Header.Get("X-Forwarded-Host"))),
		slog.String("uri", s.escapeNewlines(r.Header.Get("X-Forwarded-Uri"))),
		slog.String("source_ip", s.escapeNewlines(r.Header.Get("X-Forwarded-For"))),
		slog.String("cookies", sb.String()),
	)
	return logger
}
