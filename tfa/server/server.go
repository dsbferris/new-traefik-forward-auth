package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"

	mux "github.com/traefik/traefik/v2/pkg/muxer/http"

	"github.com/dsbferris/traefik-forward-auth/tfa/appconfig"
	"github.com/dsbferris/traefik-forward-auth/tfa/auth"
	"github.com/dsbferris/traefik-forward-auth/tfa/provider"
)

// Server contains router and handler methods
type Server struct {
	muxer  *mux.Muxer
	log    *logrus.Logger
	config *appconfig.AppConfig
	a      *auth.Auth
}

// NewServer creates a new server object and builds router
func NewServer(log *logrus.Logger, c *appconfig.AppConfig) *Server {
	s := &Server{log: log, config: c, a: auth.NewAuth(c)}
	s.buildRoutes()
	return s
}

func (s *Server) escapeNewlines(data string) string {
	escapedData := strings.ReplaceAll(data, "\n", "")
	escapedData = strings.ReplaceAll(escapedData, "\r", "")
	return escapedData
}

func (s *Server) buildRoutes() {
	var err error
	s.muxer, err = mux.NewMuxer()
	if err != nil {
		s.log.Fatal(err)
	}

	// Let's build a router
	for name, rule := range s.config.Rules {
		matchRule := rule.FormattedRule()
		err = s.muxer.AddRoute(matchRule, 1, s.Handler(rule.Action, rule.Provider, name))
		if err != nil {
			panic(err) // should not occur because rule is validated beforehand
		}
	}

	// Add callback handler
	s.muxer.Handle(s.config.Path, s.AuthCallbackHandler())

	// Add login / logout handler
	s.muxer.Handle(s.config.Path+"/login", s.LoginHandler(s.config.DefaultProvider))
	s.muxer.Handle(s.config.Path+"/logout", s.LogoutHandler())

	// Add health check handler
	s.muxer.Handle("/healthz", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))

	// Add a default handler
	s.muxer.NewRoute().Handler(s.Handler(s.config.DefaultAction, s.config.DefaultProvider, "default"))
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

func (s *Server) Handler(action, providerName, rule string) http.HandlerFunc {
	switch action {
	case "allow":
		return s.allowHandler(rule)
	case "soft-auth":
		return s.softAuthHandler(providerName, rule)
	case "auth":
		return s.hardAuthHandler(providerName, rule)
	default:
		panic("unknown action " + action)
	}
}

// allowHandler Allows requests
func (s *Server) allowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

func (s *Server) GetUserFromCookie(r *http.Request) (*string, error) {
	// Get auth cookie
	c, err := r.Cookie(s.config.CookieName)
	if err != nil {
		return nil, nil
	}

	// Validate cookie
	user, err := s.a.ValidateCookie(r, c)
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

func (s *Server) authHandler(providerName, rule string, soft bool) http.HandlerFunc {
	p, _ := s.config.GetConfiguredProvider(providerName)

	var unauthorized func(w http.ResponseWriter)
	if soft {
		unauthorized = func(w http.ResponseWriter) {
			if s.config.SoftAuthUser == "" {
				for _, headerName := range s.config.HeaderNames {
					w.Header().Del(headerName)
				}
			} else {
				for _, headerName := range s.config.HeaderNames {
					w.Header().Set(headerName, s.config.SoftAuthUser)
				}
			}
			w.WriteHeader(200)
		}
	} else {
		unauthorized = func(w http.ResponseWriter) {
			http.Error(w, "Unauthorized", 401)
		}
	}

	forceLogin := s.LoginHandler(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		ipAddr := s.escapeNewlines(r.Header.Get("X-Forwarded-For"))
		if ipAddr == "" {
			logger.Warn("missing x-forwarded-for header")
		} else {
			ok, err := s.config.IsIPAddressAuthenticated(ipAddr)
			if err != nil {
				logger.WithField("error", err).Warn("Invalid forwarded for")
			} else if ok {
				logger.WithField("addr", ipAddr).Info("Authenticated remote address")
				w.WriteHeader(200)
				return
			}
		}

		// Explicit login route (s.config.Path+"/login") on soft-auth
		if soft {
			isForceLogin := strings.HasPrefix(r.Header.Get("X-Forwarded-Uri"), s.config.Path+"/login")
			if isForceLogin {
				forceLogin(w, r)
				return
			}
		}

		// Get user from cookie
		user, err := s.GetUserFromCookie(r)
		if err != nil {
			logger.WithField("error", err).Warn("invalid user")
			unauthorized(w)
			return
		}
		if user == nil {
			if soft {
				unauthorized(w)
				return
			} else {
				s.authRedirect(logger, w, r, p, s.a.CurrentUrl(r), false)
				return
			}
		}

		// Validate user
		valid := s.a.ValidateUser(*user, rule)
		if !valid {
			logger.WithField("user", s.escapeNewlines(*user)).Warn("Invalid user")
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
}

// softAuthHandler Soft-authenticates requests
func (s *Server) softAuthHandler(providerName, rule string) http.HandlerFunc {
	return s.authHandler(providerName, rule, true)
}

// hardAuthHandler Authenticates requests
func (s *Server) hardAuthHandler(providerName, rule string) http.HandlerFunc {
	return s.authHandler(providerName, rule, false)
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := s.escapeNewlines(r.URL.Query().Get("state"))
		if err := s.a.ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check for CSRF cookie
		c, err := s.a.FindCSRFCookie(r, state)
		if err != nil {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := s.a.ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := s.config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
				"provider":    providerName,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, s.a.ClearCSRFCookie(r, c))

		// Validate redirect
		redirectURL, err := s.a.ValidateRedirect(r, redirect)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"received_redirect": redirect,
			}).Warnf("Invalid redirect in CSRF. %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check error
		authError := r.URL.Query().Get("error")
		if authError == "login_required" || authError == "consent_required" {
			// Retry with without prompt (none) parameter
			s.authRedirect(logger, w, r, p, redirect, true)
			return
		}

		// Exchange code for token
		token, err := p.ExchangeCode(s.a.RedirectUri(r), r.URL.Query().Get("code"))
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with provider")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Get user
		user, err := p.GetUser(token, s.config.UserPath)
		if err != nil {
			logger.WithField("error", err).Error("Error getting user")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Generate cookie
		http.SetCookie(w, s.a.MakeCookie(r, user))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
			"user":     user,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
	}
}

// LoginHandler logs a user in
func (s *Server) LoginHandler(providerName string) http.HandlerFunc {
	p, _ := s.config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "Login", "default", "Handling login")
		logger.Info("Explicit user login")

		// Calculate and validate redirect
		redirect := s.a.GetRedirectURI(r)
		redirectURL, err := s.a.ValidateLoginRedirect(r, redirect)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"received_redirect": redirect,
			}).Warnf("Invalid redirect in login: %v", err)
			http.Error(w, "Invalid redirect: "+err.Error(), 400)
			return
		}

		// Get user
		user, err := s.GetUserFromCookie(r)
		if err != nil {
			logger.WithField("error", err).Warn("invalid user")
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
		s.authRedirect(logger, w, r, p, redirectURL.String(), false)
	}
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		// Clear cookie
		http.SetCookie(w, s.a.ClearCookie(r))

		// Calculate and validate redirect
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			redirect = "/"
		}
		redirectURL, err := s.a.ValidateLoginRedirect(r, redirect)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"received_redirect": redirect,
			}).Warnf("Invalid redirect in login: %v", err)
			http.Error(w, "Invalid redirect: "+err.Error(), 400)
			return
		}

		http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider, returnUrl string, forcePrompt bool) {
	// Error indicates no cookie, generate nonce
	nonce, err := s.a.Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// clean existing CSRF cookie
	for _, v := range r.Cookies() {
		if strings.Contains(v.Name, s.config.CSRFCookieName) {
			http.SetCookie(w, s.a.ClearCSRFCookie(r, v))
		}
	}
	// Set the CSRF cookie
	csrf := s.a.MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !s.config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(s.a.RedirectUri(r), s.a.MakeState(returnUrl, p, nonce), forcePrompt)
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := s.log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    s.escapeNewlines(r.Header.Get("X-Forwarded-Method")),
		"proto":     s.escapeNewlines(r.Header.Get("X-Forwarded-Proto")),
		"host":      s.escapeNewlines(r.Header.Get("X-Forwarded-Host")),
		"uri":       s.escapeNewlines(r.Header.Get("X-Forwarded-Uri")),
		"source_ip": s.escapeNewlines(r.Header.Get("X-Forwarded-For")),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}
