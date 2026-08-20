package safedial

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ContextDialer is the subset of net.Dialer used to open connections after
// destination validation.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewDialContext returns a DialContext function that validates every
// destination against the policy before connecting through base. A nil base
// uses a zero net.Dialer. Only tcp, tcp4, and tcp6 networks are permitted.
//
// Hostnames are resolved first and each resolved address is validated; the
// connection is then made to a validated IP directly, so a hostile resolver
// cannot rebind the name between validation and dialing. IP literals keep
// their IPv6 zone when dialed.
//
// Use this for non-HTTP protocols or hand-built transports. For HTTP,
// prefer NewHTTPClient or NewTransport.
func NewDialContext(base ContextDialer, opts ...Option) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return newConfig(opts).dialFunc(base)
}

func (c *config) dialFunc(base ContextDialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if base == nil {
		base = &net.Dialer{}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return c.dial(ctx, base, network, addr)
	}
}

func (c *config) dial(
	ctx context.Context,
	dialer ContextDialer,
	network string,
	addr string,
) (net.Conn, error) {
	lookupNetwork := "ip"
	switch network {
	case "tcp":
	case "tcp4":
		lookupNetwork = "ip4"
	case "tcp6":
		lookupNetwork = "ip6"
	default:
		return nil, fmt.Errorf("network %q not allowed: only tcp, tcp4, and tcp6 are supported", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host/port %q: %w", addr, err)
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if c.isBlockedAddr(ip) {
			return nil, &BlockedError{Host: host, Addr: ip.WithZone("").Unmap()}
		}
		return dialer.DialContext(ctx, network, addr)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, lookupNetwork, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", host)
	}
	// Reject when ANY resolved address is blocked so a single tainted DNS
	// answer short-circuits the dial rather than racing it.
	for _, ip := range ips {
		if c.isBlockedAddr(ip) {
			return nil, &BlockedError{Host: host, Addr: ip.Unmap()}
		}
	}
	// Dial a validated IP directly. Dialing by hostname would re-resolve,
	// letting a hostile resolver swap in a private IP after validation
	// (DNS rebinding). TLS verification still uses the URL hostname via
	// the transport's TLS config.
	return dialValidatedIPs(ctx, dialer, network, port, ips)
}

func dialValidatedIPs(
	ctx context.Context,
	dialer ContextDialer,
	network string,
	port string,
	ips []netip.Addr,
) (net.Conn, error) {
	var firstErr error
	for i, ip := range ips {
		dialCtx := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			// Divide the remaining deadline across the remaining
			// addresses so one black-holed address cannot consume
			// the whole budget.
			dialCtx, cancel = context.WithDeadline(
				ctx,
				dialAttemptDeadline(time.Now(), deadline, len(ips)-i),
			)
		}
		conn, dialErr := dialer.DialContext(
			dialCtx,
			network,
			net.JoinHostPort(ip.Unmap().String(), port),
		)
		cancel()
		if dialErr == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = dialErr
		}
	}
	return nil, firstErr
}

func dialAttemptDeadline(now, deadline time.Time, attemptsRemaining int) time.Time {
	return now.Add(deadline.Sub(now) / time.Duration(attemptsRemaining))
}
