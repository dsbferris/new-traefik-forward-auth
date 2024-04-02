package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dsbferris/new-traefik-forward-auth/internal/appconfig"
	"github.com/dsbferris/new-traefik-forward-auth/internal/provider"
)

// Request Validation
var (
	ErrCookieInvalidFormat = errors.New("invalid cookie format")
	ErrCookieMacDecode     = errors.New("unable to decode cookie mac")
	ErrCookieMacGenerate   = errors.New("unable to generate mac")

	// InvalidSignature signifies one of:
	// 1. mac signature was badly computed
	// 2. mac signature was modified
	// 3. signature format was changed between versions
	// 4. secret was rotated
	ErrCookieInvalidSignature = errors.New("invalid mac signature")

	ErrCookieExpiryParse = errors.New("unable to parse cookie expiry")
	ErrCookieExpired     = errors.New("cookie has expired")

	ErrRedirectScheme        = errors.New("invalid redirect: scheme mismatch")
	ErrRedirectHost          = errors.New("invalid redirect: host mismatch")
	ErrRedirectParse         = errors.New("unable to parse redirect")
	ErrRedirectUrl           = errors.New("invalid redirect URL scheme")
	ErrRedirectHostExpected  = errors.New("redirect host does not match any expected hosts (should match cookie domain when using auth host)")
	ErrRedirectHostRequested = errors.New("redirect host does not match request host (must match when not using auth host)")

	ErrCsrfInvalidValue = errors.New("invalid CSRF cookie value")
	ErrCsrfStateMatch   = errors.New("state of CSRF cookie does not match")
	ErrCsrfStateFormat  = errors.New("invalid CSRF state format")
	ErrCsrfStateValue   = errors.New("invalid CSRF state value")
)

type Auth struct {
	config *appconfig.AppConfig
}

func NewAuth(config *appconfig.AppConfig) *Auth {
	return &Auth{config: config}
}

// ValidateCookie verifies that a cookie matches the expected format of:
// Cookie = hash(secret, cookie domain, user, expires)|expires|user
func (a *Auth) ValidateCookie(r *http.Request, c *http.Cookie) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", ErrCookieInvalidFormat
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrCookieMacDecode
	}

	expectedSignature := a.CookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", ErrCookieMacGenerate
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", ErrCookieInvalidSignature
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", ErrCookieExpiryParse
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", ErrCookieExpired
	}

	// Looks valid
	return parts[2], nil
}

// ValidateUser checks if the given user matches either a whitelisted
// user, as defined by the "whitelist" config parameter. Or is part of
// a permitted domain, as defined by the "domains" config parameter
func (a *Auth) ValidateUser(user string) bool {
	// Use global config by default
	whitelist := a.config.Whitelist.Users
	domains := a.config.Whitelist.Domains

	// Do we have any validation to perform?
	if len(whitelist) == 0 && len(domains) == 0 {
		return true
	}

	// Email whitelist validation
	if len(whitelist) > 0 {
		if a.validateWhitelist(user, whitelist) {
			return true
		}

		// If we're not matching *either*, stop here
		if !a.config.Whitelist.MatchUserOrDomain {
			return false
		}
	}

	// Domain validation
	if len(domains) > 0 {
		if a.validateDomains(user, domains) {
			return true
		}
	}

	return false
}

// validateWhitelist checks if the email is in whitelist
func (a *Auth) validateWhitelist(user string, whitelist []string) bool {
	for _, whitelist := range whitelist {
		if user == whitelist {
			return true
		}
	}
	return false
}

// validateDomains checks if the email matches a whitelisted domain
func (a *Auth) validateDomains(user string, domains []string) bool {
	parts := strings.Split(user, "@")
	if len(parts) < 2 {
		return false
	}
	emailDomain := strings.ToLower(parts[1])
	for _, domain := range domains {
		if domain == emailDomain {
			return true
		}
	}
	return false
}

func (a *Auth) GetRedirectURI(r *http.Request) string {
	redirect := r.URL.Query().Get("redirect")
	if redirect != "" {
		return redirect
	}
	forwardedURI := r.Header.Get("X-Forwarded-Uri")
	if forwardedURI != "" {
		u, err := url.ParseRequestURI(forwardedURI)
		if err == nil {
			redirect = u.Query().Get("redirect")
			if redirect != "" {
				return redirect
			}
		}
	}
	return "/"
}

func (a *Auth) ValidateLoginRedirect(r *http.Request, redirect string) (*url.URL, error) {
	u, err := url.ParseRequestURI(redirect)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	requestScheme := r.Header.Get("X-Forwarded-Proto")
	requestHost := r.Header.Get("X-Forwarded-Host")
	if u.Scheme != "" && u.Scheme != requestScheme {
		return nil, ErrRedirectScheme
	}
	if u.Host != "" && u.Host != requestHost {
		return nil, ErrRedirectHost
	}

	u.Scheme = requestScheme
	u.Host = requestHost
	return u, nil
}

// ValidateRedirect validates that the given redirect is valid and permitted for
// the given request
func (a *Auth) ValidateRedirect(r *http.Request, redirect string) (*url.URL, error) {
	redirectURL, err := url.Parse(redirect)

	if err != nil {
		return nil, ErrRedirectParse
	}

	if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
		return nil, ErrRedirectUrl
	}

	// If we're using an auth domain?
	if use, base := a.UseAuthDomain(r); use {
		// If we are using an auth domain, they redirect must share a common
		// suffix with the requested redirect
		if !strings.HasSuffix(redirectURL.Host, base) {
			return nil, ErrRedirectHostExpected
		}
	} else {
		// If not, we should only ever redirect to the same domain
		if redirectURL.Host != r.Header.Get("X-Forwarded-Host") {
			return nil, ErrRedirectHostRequested
		}
	}

	return redirectURL, nil
}

// Utility methods

// Get the request base from forwarded request
func (a *Auth) RedirectBase(r *http.Request) string {
	return fmt.Sprintf("%s://%s", r.Header.Get("X-Forwarded-Proto"), r.Host)
}

// Return url
func (a *Auth) CurrentUrl(r *http.Request) string {
	return fmt.Sprintf("%s%s", a.RedirectBase(r), r.URL.Path)
}

// Get oauth redirect uri
func (a *Auth) RedirectUri(r *http.Request) string {
	if use, _ := a.UseAuthDomain(r); use {
		p := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", p, a.config.AuthHost, a.config.UrlPath)
	}

	return fmt.Sprintf("%s%s", a.RedirectBase(r), a.config.UrlPath)
}

// Should we use auth host + what it is
func (a *Auth) UseAuthDomain(r *http.Request) (bool, string) {
	if a.config.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := a.MatchCookieDomains(r.Host)

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := a.MatchCookieDomains(a.config.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// MakeCookie creates an auth cookie
func (a *Auth) MakeCookie(r *http.Request, user string) *http.Cookie {
	expires := a.CookieExpiry()
	mac := a.CookieSignature(r, user, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), user)

	return &http.Cookie{
		Name:     a.config.Cookie.Name,
		Value:    value,
		Path:     "/",
		Domain:   a.CookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.Cookie.Insecure,
		Expires:  expires,
	}
}

// ClearCookie clears the auth cookie
func (a *Auth) ClearCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     a.config.Cookie.Name,
		Value:    "",
		Path:     "/",
		Domain:   a.CookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.Cookie.Insecure,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

func (a *Auth) buildCSRFCookieName(nonce string) string {
	return a.config.Cookie.CSRFName + "_" + nonce[:6]
}

// MakeCSRFCookie makes a csrf cookie (used during login only)
//
// Note, CSRF cookies live shorter than auth cookies, a fixed 1h.
// That's because some CSRF cookies may belong to auth flows that don't complete
// and thus may not get cleared by ClearCookie.
func (a *Auth) MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     a.buildCSRFCookieName(nonce),
		Value:    nonce,
		Path:     "/",
		Domain:   a.CsrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.Cookie.Insecure,
		Expires:  time.Now().Local().Add(time.Hour * 1),
	}
}

// ClearCSRFCookie makes an expired csrf cookie to clear csrf cookie
func (a *Auth) ClearCSRFCookie(r *http.Request, c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     "/",
		Domain:   a.CsrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.Cookie.Insecure,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// FindCSRFCookie extracts the CSRF cookie from the request based on state.
func (a *Auth) FindCSRFCookie(r *http.Request, state string) (c *http.Cookie, err error) {
	// Check for CSRF cookie
	return r.Cookie(a.buildCSRFCookieName(state))
}

// ValidateCSRFCookie validates the csrf cookie against state
func (a *Auth) ValidateCSRFCookie(c *http.Cookie, state string) (valid bool, provider string, redirect string, err error) {
	if len(c.Value) != 32 {
		return false, "", "", ErrCsrfInvalidValue
	}

	// Check nonce match
	if c.Value != state[:32] {
		return false, "", "", ErrCsrfStateMatch
	}

	// Extract provider
	params := state[33:]
	split := strings.Index(params, ":")
	if split == -1 {
		return false, "", "", ErrCsrfStateFormat
	}

	// Valid, return provider and redirect
	return true, params[:split], params[split+1:], nil
}

// MakeState generates a state value
func (a *Auth) MakeState(returnUrl string, p provider.Provider, nonce string) string {
	return fmt.Sprintf("%s:%s:%s", nonce, p.Name(), returnUrl)
}

// ValidateState checks whether the state is of right length.
func (a *Auth) ValidateState(state string) error {
	if len(state) < 34 {
		return ErrCsrfStateValue
	}
	return nil
}

// Nonce generates a random nonce
func (a *Auth) Nonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", nonce), nil
}

// Cookie domain
func (a *Auth) CookieDomain(r *http.Request) string {
	// Check if any of the given cookie domains matches
	_, domain := a.MatchCookieDomains(r.Host)
	return domain
}

// Cookie domain
func (a *Auth) CsrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := a.UseAuthDomain(r); use {
		host = domain
	} else {
		host = r.Host
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// Return matching cookie domain if exists
func (a *Auth) MatchCookieDomains(domain string) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range a.config.Cookie.Domains {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}

	return false, p[0]
}

// Create cookie hmac
func (a *Auth) CookieSignature(r *http.Request, email, expires string) string {
	// TODO switch to SHA3_512 or so
	hash := hmac.New(sha256.New, []byte(a.config.Cookie.Secret))
	hash.Write([]byte(a.CookieDomain(r)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expiry
func (a *Auth) CookieExpiry() time.Time {
	return time.Now().Local().Add(a.config.Cookie.Lifetime)
}
