package safedial

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// RedirectPolicy selects how clients built by NewHTTPClient treat HTTP
// redirects.
type RedirectPolicy int

const (
	// RedirectGuarded follows up to 10 redirects to any http or https
	// destination. Every hop is still validated by the guarded dialer,
	// and redirects to blocked IP literals are rejected before a request
	// is attempted.
	RedirectGuarded RedirectPolicy = iota
	// RedirectSameOrigin allows only method-preserving redirects within
	// the original scheme, host, and port. Use it when a redirect must
	// not leak credentials or request bodies to another host, such as
	// OAuth token or revocation endpoints.
	RedirectSameOrigin
	// RedirectDeny rejects every redirect.
	RedirectDeny
)

// CheckSameOriginRedirect allows only method-preserving redirects within the
// original scheme, host, and port. It can be used directly as an
// http.Client CheckRedirect.
func CheckSameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	origin := via[0]
	previous := via[len(via)-1]
	if req.Method != previous.Method {
		return fmt.Errorf("redirect changed method from %s to %s", previous.Method, req.Method)
	}
	if req.URL.Scheme != origin.URL.Scheme ||
		!strings.EqualFold(req.URL.Hostname(), origin.URL.Hostname()) ||
		normalizedPort(req.URL) != normalizedPort(origin.URL) {
		return fmt.Errorf("redirect must stay on origin %q", origin.URL.Scheme+"://"+origin.URL.Host)
	}
	return nil
}

func normalizedPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func (c *config) checkRedirect(req *http.Request, via []*http.Request) error {
	if c.redirect == RedirectDeny {
		return fmt.Errorf("redirect to %q blocked: redirects are not allowed", req.URL.Redacted())
	}
	// Mirror the default client's redirect cap.
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to non-HTTP scheme %q blocked", req.URL.Scheme)
	}
	// Defense in depth: reject redirects to blocked IP literals before
	// the request is attempted. Hostnames are validated post-resolution
	// by the guarded dialer.
	if ip, err := netip.ParseAddr(req.URL.Hostname()); err == nil && c.isBlockedAddr(ip) {
		return fmt.Errorf("redirect blocked: %w", &BlockedError{
			Host: req.URL.Host,
			Addr: ip.WithZone("").Unmap(),
		})
	}
	if c.redirect == RedirectSameOrigin {
		return CheckSameOriginRedirect(req, via)
	}
	return nil
}

// NewTransport returns a clone of base (or of http.DefaultTransport when
// base is nil) whose every connection goes through the guarded dialer.
// Proxies and alternate dial paths are cleared so the guard cannot be
// bypassed; all other transport settings are preserved.
//
// When base is nil and http.DefaultTransport has been globally replaced
// with something other than *http.Transport, it cannot be guarded and
// NewTransport panics rather than silently substituting a blank transport.
func NewTransport(base *http.Transport, opts ...Option) *http.Transport {
	return newConfig(opts).transport(base)
}

func (c *config) transport(base *http.Transport) *http.Transport {
	transport := base
	if transport == nil {
		t, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			panic(fmt.Sprintf(
				"safedial: http.DefaultTransport %T cannot be guarded: only *http.Transport is supported",
				http.DefaultTransport,
			))
		}
		transport = t
	}
	transport = transport.Clone()

	// Force every connection through the guarded dialer: no proxies and
	// no alternate dial paths that would bypass it.
	transport.Proxy = nil
	//nolint:staticcheck // Deprecated fields are cleared so the guarded DialContext is authoritative.
	transport.Dial = nil
	//nolint:staticcheck // Deprecated fields are cleared so the guarded DialContext is authoritative.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.DialContext = c.dialFunc(nil)
	return transport
}

// NewHTTPClient returns an *http.Client that blocks private and special-use
// destinations unless explicitly allowed. It validates and dials resolved
// IPs directly to prevent DNS rebinding and applies the configured redirect
// policy. Base client timeouts, cookie jar, and non-routing transport
// settings are preserved; a nil base gets a 30 second timeout.
//
// The guard must own the dial path, so only a nil or *http.Transport base
// transport can be preserved. Any other RoundTripper (tracing wrappers,
// test doubles) cannot be guarded and NewHTTPClient panics rather than
// silently replacing it; unwrap to the underlying *http.Transport first.
// The same applies to a globally replaced http.DefaultTransport when base
// or its transport is nil.
func NewHTTPClient(base *http.Client, opts ...Option) *http.Client {
	cfg := newConfig(opts)
	timeout := 30 * time.Second
	var baseTransport *http.Transport
	var jar http.CookieJar
	if base != nil {
		timeout = base.Timeout
		jar = base.Jar
		switch t := base.Transport.(type) {
		case nil:
		case *http.Transport:
			baseTransport = t
		default:
			panic(fmt.Sprintf(
				"safedial: base transport %T cannot be guarded: only nil or *http.Transport is supported",
				base.Transport,
			))
		}
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     cfg.transport(baseTransport),
		CheckRedirect: cfg.checkRedirect,
		Jar:           jar,
	}
}
