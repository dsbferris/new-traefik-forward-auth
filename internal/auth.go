package tfa

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

	"github.com/dsbferris/traefik-forward-auth/internal/provider"
	"github.com/dsbferris/traefik-forward-auth/types"
)

// Request Validation

const (
	StrInvalidFormat       = "invalid cookie format"
	StrUnableToDecodeMac   = "unable to decode cookie mac"
	StrUnableToGenerateMac = "unable to generate mac"
	// InvalidSignature signifies one of:
	// 1. mac signature was badly computed
	// 2. mac signature was modified
	// 3. signature format was changed between versions
	// 4. secret was rotated
	StrInvalidSignature    = "invalid mac signature"
	StrUnableToParseExpiry = "unable to parse cookie expiry"
	StrCookieExpired       = "cookie has expired"

	StrInvalidRedirectSchemeMismatch    = "invalid redirect: scheme mismatch"
	StrInvalidRedirectHostMismatch      = "invalid redirect: host mismatch"
	StrUnableToParseRedirect            = "unable to parse redirect"
	StrInvalidRedirectUrlScheme         = "invalid redirect URL scheme"
	StrRedirectHostDoesNotMatchExpected = "redirect host does not match any expected hosts (should match cookie domain when using auth host)"
	StrRedirectHostDoesNotMatchRequest  = "redirect host does not match request host (must match when not using auth host)"

	StrInvalidCsrfCookieValue      = "invalid CSRF cookie value"
	StrCsrfCookieDoesNotMatchState = "state of CSRF cookie does not match"
	StrInvalidCsrfStateFormat      = "invalid CSRF state format"
	StrInvalidCsrfStateValue       = "invalid CSRF state value"
)

func checkProbeToken(cookie string) (user string, ok bool) {
	for _, probeToken := range config.ProbeToken {
		if cookie == probeToken {
			return config.ProbeTokenUser, true
		}
	}
	return "", false
}

// ValidateCookie verifies that a cookie matches the expected format of:
// Cookie = hash(secret, cookie domain, user, expires)|expires|user
func ValidateCookie(r *http.Request, c *http.Cookie) (string, error) {
	if user, ok := checkProbeToken(c.Value); ok {
		return user, nil
	}

	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New(StrInvalidFormat)
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New(StrUnableToDecodeMac)
	}

	expectedSignature := cookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New(StrUnableToGenerateMac)
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", errors.New(StrInvalidSignature)
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New(StrUnableToParseExpiry)
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", errors.New(StrCookieExpired)
	}

	// Looks valid
	return parts[2], nil
}

// ValidateUser checks if the given user matches either a whitelisted
// user, as defined by the "whitelist" config parameter. Or is part of
// a permitted domain, as defined by the "domains" config parameter
func ValidateUser(user, ruleName string) bool {
	// Use global config by default
	whitelist := config.Whitelist
	domains := config.Domains

	if rule, ok := config.Rules[ruleName]; ok {
		// Override with rule config if found
		if len(rule.Whitelist) > 0 || len(rule.Domains) > 0 {
			whitelist = rule.Whitelist
			domains = rule.Domains
		}
	}

	// Do we have any validation to perform?
	if len(whitelist) == 0 && len(domains) == 0 {
		return true
	}

	// Email whitelist validation
	if len(whitelist) > 0 {
		if ValidateWhitelist(user, whitelist) {
			return true
		}

		// If we're not matching *either*, stop here
		if !config.MatchWhitelistOrDomain {
			return false
		}
	}

	// Domain validation
	if len(domains) > 0 && ValidateDomains(user, domains) {
		return true
	}

	return false
}

// ValidateWhitelist checks if the email is in whitelist
func ValidateWhitelist(user string, whitelist types.CommaSeparatedList) bool {
	for _, whitelist := range whitelist {
		if user == whitelist {
			return true
		}
	}
	return false
}

// ValidateDomains checks if the email matches a whitelisted domain
func ValidateDomains(user string, domains types.CommaSeparatedList) bool {
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

func GetRedirectURI(r *http.Request) string {
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

func ValidateLoginRedirect(r *http.Request, redirect string) (*url.URL, error) {
	u, err := url.ParseRequestURI(redirect)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	requestScheme := r.Header.Get("X-Forwarded-Proto")
	requestHost := r.Header.Get("X-Forwarded-Host")
	if u.Scheme != "" && u.Scheme != requestScheme {
		return nil, fmt.Errorf(StrInvalidRedirectSchemeMismatch)
	}
	if u.Host != "" && u.Host != requestHost {
		return nil, fmt.Errorf(StrInvalidRedirectHostMismatch)
	}

	u.Scheme = requestScheme
	u.Host = requestHost
	return u, nil
}

// ValidateRedirect validates that the given redirect is valid and permitted for
// the given request
func ValidateRedirect(r *http.Request, redirect string) (*url.URL, error) {
	redirectURL, err := url.Parse(redirect)

	if err != nil {
		return nil, errors.New(StrUnableToParseRedirect)
	}

	if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
		return nil, errors.New(StrInvalidRedirectUrlScheme)
	}

	// If we're using an auth domain?
	if use, base := useAuthDomain(r); use {
		// If we are using an auth domain, they redirect must share a common
		// suffix with the requested redirect
		if !strings.HasSuffix(redirectURL.Host, base) {
			return nil, errors.New(StrRedirectHostDoesNotMatchExpected)
		}
	} else {
		// If not, we should only ever redirect to the same domain
		if redirectURL.Host != r.Header.Get("X-Forwarded-Host") {
			return nil, errors.New(StrRedirectHostDoesNotMatchRequest)
		}
	}

	return redirectURL, nil
}

// Utility methods

// Get the request base from forwarded request
func redirectBase(r *http.Request) string {
	return fmt.Sprintf("%s://%s", r.Header.Get("X-Forwarded-Proto"), r.Host)
}

// Return url
func currentUrl(r *http.Request) string {
	return fmt.Sprintf("%s%s", redirectBase(r), r.URL.Path)
}

// Get oauth redirect uri
func redirectUri(r *http.Request) string {
	if use, _ := useAuthDomain(r); use {
		p := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", p, config.AuthHost, config.Path)
	}

	return fmt.Sprintf("%s%s", redirectBase(r), config.Path)
}

// Should we use auth host + what it is
func useAuthDomain(r *http.Request) (bool, string) {
	if config.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := matchCookieDomains(r.Host)

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := matchCookieDomains(config.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// MakeCookie creates an auth cookie
func MakeCookie(r *http.Request, user string) *http.Cookie {
	expires := cookieExpiry()
	mac := cookieSignature(r, user, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), user)

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  expires,
	}
}

// ClearCookie clears the auth cookie
func ClearCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     config.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

func buildCSRFCookieName(nonce string) string {
	return config.CSRFCookieName + "_" + nonce[:6]
}

// MakeCSRFCookie makes a csrf cookie (used during login only)
//
// Note, CSRF cookies live shorter than auth cookies, a fixed 1h.
// That's because some CSRF cookies may belong to auth flows that don't complete
// and thus may not get cleared by ClearCookie.
func MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     buildCSRFCookieName(nonce),
		Value:    nonce,
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * 1),
	}
}

// ClearCSRFCookie makes an expired csrf cookie to clear csrf cookie
func ClearCSRFCookie(r *http.Request, c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// FindCSRFCookie extracts the CSRF cookie from the request based on state.
func FindCSRFCookie(r *http.Request, state string) (c *http.Cookie, err error) {
	// Check for CSRF cookie
	return r.Cookie(buildCSRFCookieName(state))
}

// ValidateCSRFCookie validates the csrf cookie against state
func ValidateCSRFCookie(c *http.Cookie, state string) (valid bool, provider string, redirect string, err error) {
	if len(c.Value) != 32 {
		return false, "", "", errors.New(StrInvalidCsrfCookieValue)
	}

	// Check nonce match
	if c.Value != state[:32] {
		return false, "", "", errors.New(StrCsrfCookieDoesNotMatchState)
	}

	// Extract provider
	params := state[33:]
	split := strings.Index(params, ":")
	if split == -1 {
		return false, "", "", errors.New(StrInvalidCsrfStateFormat)
	}

	// Valid, return provider and redirect
	return true, params[:split], params[split+1:], nil
}

// MakeState generates a state value
func MakeState(returnUrl string, p provider.Provider, nonce string) string {
	return fmt.Sprintf("%s:%s:%s", nonce, p.Name(), returnUrl)
}

// ValidateState checks whether the state is of right length.
func ValidateState(state string) error {
	if len(state) < 34 {
		return errors.New(StrInvalidCsrfStateValue)
	}
	return nil
}

// Nonce generates a random nonce
func Nonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", nonce), nil
}

// Cookie domain
func cookieDomain(r *http.Request) string {
	// Check if any of the given cookie domains matches
	_, domain := matchCookieDomains(r.Host)
	return domain
}

// Cookie domain
func csrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := useAuthDomain(r); use {
		host = domain
	} else {
		host = r.Host
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// Return matching cookie domain if exists
func matchCookieDomains(domain string) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range config.CookieDomains {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}

	return false, p[0]
}

// Create cookie hmac
func cookieSignature(r *http.Request, email, expires string) string {
	hash := hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(cookieDomain(r)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expiry
func cookieExpiry() time.Time {
	return time.Now().Local().Add(config.Lifetime)
}
