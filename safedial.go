// Package safedial hardens outbound requests against server-side request
// forgery (SSRF) when the destination host is influenced by someone other
// than the operator of the calling service: end users, org admins, webhook
// subscriptions, OAuth discovery documents, and similar.
//
// The guard validates every destination IP address after DNS resolution and
// dials the validated address directly, so a hostile resolver cannot swap in
// a private address between validation and connection (DNS rebinding).
// Private, loopback, link-local, multicast, and special-use ranges are
// blocked by default; deployments reach intentionally internal destinations
// through an explicit allowlist.
//
// This package is not meant to wrap destinations that only the deployment
// operator controls (their own OIDC issuer, SMTP smarthost, telemetry
// endpoint). Operators legitimately point those at internal addresses, and
// they already control the process.
package safedial

import (
	"fmt"
	"net/netip"
)

// wellKnownNAT64Prefix is the RFC 6052 well-known prefix. Addresses inside
// it embed an IPv4 destination, which is extracted and validated with the
// full IPv4 policy so a translator cannot smuggle traffic to blocked
// targets.
var wellKnownNAT64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// extraBlockedPrefixes covers special-use ranges that netip.Addr's built-in
// classifications do not recognize.
var extraBlockedPrefixes = []netip.Prefix{
	// IPv4 special-use ranges.
	netip.MustParsePrefix("0.0.0.0/8"),       // RFC 1122 "this network".
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT.
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890 IETF protocol assignments.
	netip.MustParsePrefix("192.0.2.0/24"),    // RFC 5737 documentation.
	netip.MustParsePrefix("192.31.196.0/24"), // RFC 7535 AS112-v4.
	netip.MustParsePrefix("192.52.193.0/24"), // RFC 7450 AMT.
	netip.MustParsePrefix("192.88.99.0/24"),  // RFC 7526 deprecated 6to4 relay anycast.
	netip.MustParsePrefix("192.175.48.0/24"), // RFC 7534 direct delegation AS112 service.
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmarking.
	netip.MustParsePrefix("198.51.100.0/24"), // RFC 5737 documentation.
	netip.MustParsePrefix("203.0.113.0/24"),  // RFC 5737 documentation.
	netip.MustParsePrefix("240.0.0.0/4"),     // RFC 1112 reserved.

	// IPv6 special-use ranges not covered by stdlib.
	// Deprecated IPv4-embedding forms are blocked outright rather than
	// decoded like the NAT64 well-known prefix: RFC 4291 deprecated
	// IPv4-compatible addresses and RFC 2765 SIIT translation has no
	// modern deployment, so a translator routing them is not a
	// supported path to otherwise-public IPv4 targets.
	netip.MustParsePrefix("::/96"),           // RFC 4291 deprecated IPv4-compatible.
	netip.MustParsePrefix("::ffff:0:0:0/96"), // RFC 2765 SIIT IPv4-translated.
	// RFC 8215 permits deployment-chosen embedding layouts, so its IPv4
	// destination cannot be decoded reliably. Deployments using a local
	// NAT64 prefix can declare it with WithNAT64Prefixes.
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),          // RFC 6666 discard-only.
	netip.MustParsePrefix("100:0:0:1::/64"),    // RFC 9780 dummy prefix.
	netip.MustParsePrefix("2001::/23"),         // RFC 2928 IETF protocol assignments.
	netip.MustParsePrefix("2001:db8::/32"),     // RFC 3849 documentation.
	netip.MustParsePrefix("2002::/16"),         // RFC 3056 6to4.
	netip.MustParsePrefix("2620:4f:8000::/48"), // RFC 7534 direct delegation AS112 service.
	netip.MustParsePrefix("3fff::/20"),         // RFC 9637 documentation.
	netip.MustParsePrefix("5f00::/16"),         // RFC 9602 segment routing SIDs.
	netip.MustParsePrefix("fec0::/10"),         // RFC 3879 deprecated site-local addresses.
}

type config struct {
	allowed  []netip.Prefix
	nat64    []netip.Prefix
	redirect RedirectPolicy
}

func newConfig(opts []Option) *config {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// Option configures the destination policy.
type Option func(*config)

// WithAllowedPrefixes exempts destinations inside the given CIDRs from
// blocking. Allowed prefixes take precedence over every block rule, so scope
// them as narrowly as possible. Parse operator-supplied values with
// ParseAllowedPrefix so IPv4-mapped IPv6 forms cannot bypass the policy.
func WithAllowedPrefixes(prefixes ...netip.Prefix) Option {
	return func(cfg *config) {
		cfg.allowed = append(cfg.allowed, prefixes...)
	}
}

// WithNAT64Prefixes declares deployment-specific NAT64 translation prefixes
// (RFC 8215 network-specific prefixes). Addresses inside a declared prefix
// have their embedded IPv4 destination extracted and validated with the full
// IPv4 policy, exactly like the RFC 6052 well-known prefix, which is always
// handled. Each prefix must be an IPv6 prefix of an RFC 6052 length (32,
// 40, 48, 56, 64, or 96), as produced by ParseNAT64Prefix; other values
// panic.
func WithNAT64Prefixes(prefixes ...netip.Prefix) Option {
	for _, prefix := range prefixes {
		if err := validateNAT64Prefix(prefix); err != nil {
			panic(fmt.Sprintf("safedial: %v", err))
		}
	}
	return func(cfg *config) {
		cfg.nat64 = append(cfg.nat64, prefixes...)
	}
}

// WithRedirectPolicy sets how clients built by NewHTTPClient treat HTTP
// redirects. The default is RedirectGuarded. The policy has no effect on
// NewDialContext or NewTransport, which never see redirects.
func WithRedirectPolicy(policy RedirectPolicy) Option {
	return func(cfg *config) {
		cfg.redirect = policy
	}
}

// BlockedError reports a destination that was rejected by the address
// policy, as opposed to a network failure. Use errors.As to map policy
// rejections to caller-facing validation errors.
type BlockedError struct {
	// Host is the host portion of the requested address: a hostname when
	// the destination was resolved, or the literal IP that was dialed.
	Host string
	// Addr is the blocked IP address with any IPv6 zone stripped and
	// IPv4-mapped form unmapped.
	Addr netip.Addr
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf(
		"connection to %q blocked: %s is in a private or reserved range not allowed by policy",
		e.Host, e.Addr,
	)
}

// ParseAllowedPrefix parses an allowed CIDR and converts IPv4-mapped IPv6
// prefixes to equivalent IPv4 prefixes. Prefixes shorter than the 96-bit
// IPv4-mapped marker cannot be represented as IPv4 ranges.
func ParseAllowedPrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !prefix.Addr().Is4In6() {
		return prefix, nil
	}
	if prefix.Bits() < 96 {
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped IPv6 prefix length must be at least 96 bits")
	}
	return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96), nil
}

// ParseNAT64Prefix parses an RFC 6052 NAT64 translation prefix for
// WithNAT64Prefixes. Every embedding layout defined by RFC 6052 is
// supported: IPv6 prefixes of length 32, 40, 48, 56, 64, or 96.
func ParseNAT64Prefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	if err := validateNAT64Prefix(prefix); err != nil {
		return netip.Prefix{}, err
	}
	return prefix, nil
}

func validateNAT64Prefix(prefix netip.Prefix) error {
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return fmt.Errorf("NAT64 prefix %q must be IPv6", prefix)
	}
	switch prefix.Bits() {
	case 32, 40, 48, 56, 64, 96:
		return nil
	default:
		return fmt.Errorf("NAT64 prefix %q must have an RFC 6052 length (32, 40, 48, 56, 64, or 96)", prefix)
	}
}

// CheckAddr validates a single IP address against the destination policy.
// It returns a *BlockedError when the address is blocked and nil otherwise.
// Use it for pre-checks on caller-supplied IP literals; hostname-based
// destinations must go through the guarded dialer instead so the
// post-resolution addresses are what get validated.
func CheckAddr(addr netip.Addr, opts ...Option) error {
	cfg := newConfig(opts)
	if cfg.isBlockedAddr(addr) {
		return &BlockedError{Host: addr.String(), Addr: addr.WithZone("").Unmap()}
	}
	return nil
}

// IPv4-mapped addresses are unmapped and IPv6 zones are stripped before
// checking so address forms cannot bypass prefix policy. Allowed prefixes
// take precedence.
func (c *config) isBlockedAddr(addr netip.Addr) bool {
	addr = addr.WithZone("").Unmap()
	for _, prefix := range c.allowed {
		if prefix.Contains(addr) {
			return false
		}
	}
	if wellKnownNAT64Prefix.Contains(addr) {
		return c.isBlockedAddr(embeddedIPv4(addr, 96))
	}
	for _, prefix := range c.nat64 {
		if prefix.Contains(addr) {
			return c.isBlockedAddr(embeddedIPv4(addr, prefix.Bits()))
		}
	}
	if addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() ||
		addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, prefix := range extraBlockedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// embeddedIPv4 extracts the IPv4 address from an RFC 6052 translation
// address using the section 2.2 layout for the given prefix length. The u
// octet (bits 64 to 71) is skipped where the IPv4 bits straddle it.
func embeddedIPv4(addr netip.Addr, prefixBits int) netip.Addr {
	b := addr.As16()
	var v4 [4]byte
	switch prefixBits {
	case 32:
		copy(v4[:], b[4:8])
	case 40:
		copy(v4[:3], b[5:8])
		v4[3] = b[9]
	case 48:
		copy(v4[:2], b[6:8])
		copy(v4[2:], b[9:11])
	case 56:
		v4[0] = b[7]
		copy(v4[1:], b[9:12])
	case 64:
		copy(v4[:], b[9:13])
	default:
		copy(v4[:], b[12:16])
	}
	return netip.AddrFrom4(v4)
}
