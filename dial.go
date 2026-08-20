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

// defaultDialTimeout mirrors http.DefaultTransport's 30 second dialer
// timeout.
const defaultDialTimeout = 30 * time.Second

// defaultDialer mirrors http.DefaultTransport's dialer settings so guarded
// defaults keep the standard connect timeout and keep-alive.
func defaultDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: 30 * time.Second,
	}
}

// withDefaultTimeout bounds the whole dial operation, resolution and every
// connect attempt combined, to defaultDialTimeout unless the caller's
// deadline is sooner. net.Dialer.Timeout alone is not equivalent: it
// restarts for each validated address dialed, so multiple black-holed
// addresses would multiply it, unlike http.DefaultTransport's single
// connect budget.
func withDefaultTimeout(
	next func(ctx context.Context, network, addr string) (net.Conn, error),
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		limit := time.Now().Add(defaultDialTimeout)
		if deadline, ok := ctx.Deadline(); !ok || deadline.After(limit) {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, limit)
			defer cancel()
		}
		return next(ctx, network, addr)
	}
}

// NewDialContext returns a DialContext function that validates every
// destination against the policy before connecting through base. A nil base
// uses a dialer with http.DefaultTransport's timeout and keep-alive, and
// bounds each whole dial operation, resolution and all connect attempts
// combined, by that timeout unless the caller's deadline is sooner. Only
// tcp, tcp4, and tcp6 networks are permitted.
//
// Hostnames are resolved first and each resolved address is validated; the
// connection is then made to a validated IP directly, so a hostile resolver
// cannot rebind the name between validation and dialing. IP literals keep
// their IPv6 zone when dialed.
//
// When a hostname resolves to both address families, the validated
// addresses are dialed with net.Dialer's Happy Eyeballs behavior: the
// second family starts after a short fallback delay, so base may see
// concurrent DialContext calls for one dial. A base *net.Dialer's
// FallbackDelay is honored, including a negative value to disable the
// race.
//
// Use this for non-HTTP protocols or hand-built transports. For HTTP,
// prefer NewHTTPClient or NewTransport.
func NewDialContext(base ContextDialer, opts ...Option) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return newConfig(opts).dialFunc(base)
}

func (c *config) dialFunc(base ContextDialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if base != nil {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.dial(ctx, base, network, addr)
		}
	}
	dialer := defaultDialer()
	return withDefaultTimeout(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return c.dial(ctx, dialer, network, addr)
	})
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
		if bad, blocked := c.blockedAddr(ip); blocked {
			return nil, &BlockedError{Host: host, Addr: bad}
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
		if bad, blocked := c.blockedAddr(ip); blocked {
			return nil, &BlockedError{Host: host, Addr: bad}
		}
	}
	// Dial a validated IP directly. Dialing by hostname would re-resolve,
	// letting a hostile resolver swap in a private IP after validation
	// (DNS rebinding). TLS verification still uses the URL hostname via
	// the transport's TLS config.
	return dialValidatedIPs(ctx, dialer, network, port, ips)
}

// defaultFallbackDelay mirrors net.Dialer's default delay before the
// fallback address family is dialed (Happy Eyeballs, RFC 8305).
const defaultFallbackDelay = 300 * time.Millisecond

// dialValidatedIPs connects to validated addresses, preserving the Happy
// Eyeballs behavior net.Dialer applies when dialing a hostname: the
// resolver's preferred address family gets a head start and the other
// family is raced after a short fallback delay, immediately once every
// primary attempt has failed. Without the race, one black-holed family
// would consume its whole share of the deadline before the working family
// is tried. This mirrors net.Dialer.dialParallel; a losing dial that
// completes anyway is closed.
func dialValidatedIPs(
	ctx context.Context,
	dialer ContextDialer,
	network string,
	port string,
	ips []netip.Addr,
) (net.Conn, error) {
	delay := fallbackDelay(dialer)
	var primaries, fallbacks []netip.Addr
	if delay < 0 {
		// Happy Eyeballs disabled: dial everything in sequence.
		primaries = ips
	} else {
		primaries, fallbacks = partitionByFamily(ips)
	}
	if len(fallbacks) == 0 {
		return dialSerial(ctx, dialer, network, port, primaries)
	}

	type dialResult struct {
		conn    net.Conn
		err     error
		primary bool
	}
	// Unbuffered: a losing racer blocks until the loop receives its
	// result or the function has returned, and then closes its conn.
	results := make(chan dialResult)
	returned := make(chan struct{})
	defer close(returned)

	racer := func(ctx context.Context, primary bool) {
		addrs := primaries
		if !primary {
			addrs = fallbacks
		}
		conn, err := dialSerial(ctx, dialer, network, port, addrs)
		select {
		case results <- dialResult{conn: conn, err: err, primary: primary}:
		case <-returned:
			if conn != nil {
				_ = conn.Close()
			}
		}
	}

	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	go racer(primaryCtx, true)

	fallbackTimer := time.NewTimer(delay)
	defer fallbackTimer.Stop()

	var primaryErr, fallbackErr error
	for {
		select {
		case <-fallbackTimer.C:
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel()
			go racer(fallbackCtx, false)
		case res := <-results:
			if res.err == nil {
				return res.conn, nil
			}
			if res.primary {
				primaryErr = res.err
			} else {
				fallbackErr = res.err
			}
			if primaryErr != nil && fallbackErr != nil {
				// The primary family's error is the most relevant,
				// matching net.Dialer.
				return nil, primaryErr
			}
			if res.primary && fallbackTimer.Stop() {
				// Every primary attempt failed before the fallback
				// started; start it immediately.
				fallbackTimer.Reset(0)
			}
		}
	}
}

// fallbackDelay resolves the Happy Eyeballs fallback delay for a dialer
// with net.Dialer's semantics: a positive FallbackDelay is used as-is, a
// negative one disables the race (reported as -1), and zero or any other
// dialer type gets the standard default.
func fallbackDelay(dialer ContextDialer) time.Duration {
	if d, ok := dialer.(*net.Dialer); ok {
		if d.FallbackDelay > 0 {
			return d.FallbackDelay
		}
		if d.FallbackDelay < 0 {
			return -1
		}
	}
	return defaultFallbackDelay
}

// partitionByFamily splits addresses into those sharing the first
// address's family (primaries) and the rest (fallbacks), preserving order
// within each list, mirroring net.Dialer's Happy Eyeballs partition.
func partitionByFamily(ips []netip.Addr) (primaries, fallbacks []netip.Addr) {
	if len(ips) == 0 {
		return nil, nil
	}
	primaryIs4 := ips[0].Unmap().Is4()
	for _, ip := range ips {
		if ip.Unmap().Is4() == primaryIs4 {
			primaries = append(primaries, ip)
		} else {
			fallbacks = append(fallbacks, ip)
		}
	}
	return primaries, fallbacks
}

func dialSerial(
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
	if firstErr == nil {
		firstErr = fmt.Errorf("no addresses to dial")
	}
	return nil, firstErr
}

func dialAttemptDeadline(now, deadline time.Time, attemptsRemaining int) time.Time {
	return now.Add(deadline.Sub(now) / time.Duration(attemptsRemaining))
}
