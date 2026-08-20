package safedial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testWait = 10 * time.Second

func testContext(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	return ctx
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func (f dialContextFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// closeNotifyConn signals on closed the first time Close is called.
type closeNotifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func newCloseNotifyConn(inner net.Conn) *closeNotifyConn {
	return &closeNotifyConn{Conn: inner, closed: make(chan struct{})}
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestIsBlockedAddr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		addr    string
		allowed []netip.Prefix
		nat64   []netip.Prefix
		blocked bool
	}{
		{name: "LoopbackIPv4", addr: "127.0.0.1", blocked: true},
		{name: "LoopbackIPv4Alias", addr: "127.0.0.2", blocked: true},
		{name: "LoopbackIPv6", addr: "::1", blocked: true},
		{addr: "10.0.0.1", blocked: true},
		{addr: "172.16.5.4", blocked: true},
		{addr: "192.168.1.1", blocked: true},
		{addr: "fd12:3456::1", blocked: true},
		{addr: "169.254.169.254", blocked: true},
		{name: "ZonedLinkLocalIPv6", addr: "fe80::1%eth0", blocked: true},
		{
			name:    "AllowlistedZonedLinkLocalIPv6",
			addr:    "fe80::1%eth0",
			allowed: []netip.Prefix{netip.MustParsePrefix("fe80::/10")},
			blocked: false,
		},
		{addr: "fe80::1", blocked: true},
		{addr: "0.0.0.0", blocked: true},
		{addr: "::", blocked: true},
		{addr: "224.0.0.1", blocked: true},
		{addr: "ff02::1", blocked: true},
		{addr: "100.64.0.1", blocked: true},
		{addr: "192.0.0.8", blocked: true},
		{addr: "192.0.2.1", blocked: true},
		{addr: "192.31.196.1", blocked: true},
		{addr: "192.52.193.1", blocked: true},
		{addr: "192.88.99.1", blocked: true},
		{addr: "192.175.48.1", blocked: true},
		{addr: "198.18.0.1", blocked: true},
		{addr: "198.51.100.1", blocked: true},
		{addr: "203.0.113.1", blocked: true},
		{addr: "240.0.0.1", blocked: true},
		{addr: "0.1.2.3", blocked: true},
		{name: "NAT64PublicIPv4", addr: "64:ff9b::808:808", blocked: false},
		{name: "NAT64PrivateIPv4", addr: "64:ff9b::a00:1", blocked: true},
		{name: "NAT64LoopbackIPv4", addr: "64:ff9b::7f00:1", blocked: true},
		{name: "NAT64LinkLocalIPv4", addr: "64:ff9b::a9fe:a9fe", blocked: true},
		{name: "NAT64SpecialIPv4", addr: "64:ff9b::c000:201", blocked: true},
		{
			name:    "NAT64AllowedIPv4CIDR",
			addr:    "64:ff9b::a00:1",
			allowed: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			blocked: false,
		},
		// Allowlisting a translator's IPv6 range must not skip
		// validation of the embedded IPv4 destination: NAT64 decoding
		// runs before the allowlist.
		{
			name:    "AllowlistedNAT64WrapperStillBlocksPrivate",
			addr:    "64:ff9b::a00:1",
			allowed: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
			blocked: true,
		},
		{
			name:    "AllowlistedNAT64WrapperStillBlocksMetadata",
			addr:    "64:ff9b::a9fe:a9fe",
			allowed: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
			blocked: true,
		},
		{
			name:    "AllowlistedNAT64WrapperKeepsPublic",
			addr:    "64:ff9b::808:808",
			allowed: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
			blocked: false,
		},
		{
			name:    "AllowlistedConfiguredNAT64WrapperStillBlocksPrivate",
			addr:    "64:ff9b:1:2:3:4:a00:1",
			nat64:   []netip.Prefix{netip.MustParsePrefix("64:ff9b:1:2:3:4::/96")},
			allowed: []netip.Prefix{netip.MustParsePrefix("64:ff9b:1:2:3:4::/96")},
			blocked: true,
		},
		{addr: "64:ff9b::1", blocked: true},
		{addr: "100::1", blocked: true},
		{addr: "100:0:0:1::1", blocked: true},
		{addr: "2001::1", blocked: true},
		{addr: "2001:db8::1", blocked: true},
		{addr: "2002::1", blocked: true},
		{addr: "2620:4f:8000::1", blocked: true},
		{addr: "3fff::1", blocked: true},
		{addr: "5f00::1", blocked: true},
		{name: "NAT64LocalUsePrefix", addr: "64:ff9b:1::808:808", blocked: true},
		{
			name:    "ConfiguredNAT64PrefixPublicIPv4",
			addr:    "64:ff9b:1:2:3:4:808:808",
			nat64:   []netip.Prefix{netip.MustParsePrefix("64:ff9b:1:2:3:4::/96")},
			blocked: false,
		},
		{
			name:    "ConfiguredNAT64PrefixPrivateIPv4",
			addr:    "64:ff9b:1:2:3:4:a00:1",
			nat64:   []netip.Prefix{netip.MustParsePrefix("64:ff9b:1:2:3:4::/96")},
			blocked: true,
		},
		{
			name:    "ConfiguredNAT64PrefixMetadataIPv4",
			addr:    "64:ff9b:1:2:3:4:a9fe:a9fe",
			nat64:   []netip.Prefix{netip.MustParsePrefix("64:ff9b:1:2:3:4::/96")},
			blocked: true,
		},
		// RFC 6052 section 2.4 example embeddings of 192.0.2.33 (a
		// blocked documentation address) at every defined prefix
		// length.
		{
			name:    "NSP32BlockedIPv4",
			addr:    "2001:db8:c000:221::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			blocked: true,
		},
		{
			name:    "NSP40BlockedIPv4",
			addr:    "2001:db8:1c0:2:21::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:100::/40")},
			blocked: true,
		},
		{
			name:    "NSP48BlockedIPv4",
			addr:    "2001:db8:122:c000:2:2100::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:122::/48")},
			blocked: true,
		},
		{
			name:    "NSP56BlockedIPv4",
			addr:    "2001:db8:122:3c0:0:221::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:122:300::/56")},
			blocked: true,
		},
		{
			name:    "NSP64BlockedIPv4",
			addr:    "2001:db8:122:344:c0:2:2100::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:122:344::/64")},
			blocked: true,
		},
		{
			name:    "NSP96BlockedIPv4",
			addr:    "2001:db8:122:344::c000:221",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:122:344::/96")},
			blocked: true,
		},
		// The same layouts embedding public 8.8.8.8. The NSPs sit
		// inside the otherwise-blocked 2001:db8::/32 documentation
		// range, so an allowed verdict proves the decode ran.
		{
			name:    "NSP32PublicIPv4",
			addr:    "2001:db8:808:808::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			blocked: false,
		},
		{
			name:    "NSP40PublicIPv4",
			addr:    "2001:db8:108:808:8::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:100::/40")},
			blocked: false,
		},
		{
			name:    "NSP48PublicIPv4",
			addr:    "2001:db8:122:808:8:800::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:122::/48")},
			blocked: false,
		},
		{
			name:    "NSP56PublicIPv4",
			addr:    "2001:db8:122:308:8:808::",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:122:300::/56")},
			blocked: false,
		},
		{
			name:    "NSP64PublicIPv4",
			addr:    "2001:db8:122:344:8:808:800:0",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:122:344::/64")},
			blocked: false,
		},
		{
			name:    "NSP96PublicIPv4",
			addr:    "2001:db8:122:344::808:808",
			nat64:   []netip.Prefix{netip.MustParsePrefix("2001:db8:122:344::/96")},
			blocked: false,
		},
		{name: "IPv4CompatibleLoopback", addr: "::127.0.0.1", blocked: true},
		{name: "IPv4CompatiblePrivate", addr: "::10.0.0.1", blocked: true},
		{name: "IPv4CompatiblePublic", addr: "::8.8.8.8", blocked: true},
		{name: "SIITTranslatedMetadata", addr: "::ffff:0:169.254.169.254", blocked: true},
		{name: "SIITTranslatedLoopback", addr: "::ffff:0:127.0.0.1", blocked: true},
		{name: "SIITTranslatedPublic", addr: "::ffff:0:8.8.8.8", blocked: true},
		{addr: "fec0::1", blocked: true},
		{
			name:    "AllowlistedDeprecatedSiteLocalIPv6",
			addr:    "fec0::1",
			allowed: []netip.Prefix{netip.MustParsePrefix("fec0::/10")},
			blocked: false,
		},
		{addr: "::ffff:169.254.169.254", blocked: true},
		{addr: "::ffff:127.0.0.1", blocked: true},
		{addr: "8.8.8.8", blocked: false},
		{addr: "1.1.1.1", blocked: false},
		{addr: "2606:4700:4700::1111", blocked: false},
		{
			name:    "AllowlistedLoopback",
			addr:    "127.0.0.1",
			allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			blocked: false,
		},
		{
			name:    "AllowlistedSpecialPurposeRange",
			addr:    "192.0.2.1",
			allowed: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			blocked: false,
		},
		{
			name:    "AllowlistDoesNotCoverPeer",
			addr:    "127.0.0.2",
			allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			blocked: true,
		},
		{
			name:    "AllowlistDoesNotCoverMetadata",
			addr:    "169.254.169.254",
			allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
			blocked: true,
		},
	}
	for _, tc := range cases {
		name := tc.name
		if name == "" {
			name = tc.addr
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			addr := netip.MustParseAddr(tc.addr)
			if addr.Zone() != "" {
				for _, prefix := range tc.allowed {
					require.False(t, prefix.Contains(addr))
				}
			}
			cfg := newConfig([]Option{
				WithAllowedPrefixes(tc.allowed...),
				WithNAT64Prefixes(tc.nat64...),
			})
			require.Equal(t, tc.blocked, cfg.isBlockedAddr(addr))
		})
	}
}

func TestCheckAddr(t *testing.T) {
	t.Parallel()

	require.NoError(t, CheckAddr(netip.MustParseAddr("8.8.8.8")))

	err := CheckAddr(netip.MustParseAddr("::ffff:10.0.0.1"))
	var blockedErr *BlockedError
	require.ErrorAs(t, err, &blockedErr)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), blockedErr.Addr)

	require.NoError(t, CheckAddr(
		netip.MustParseAddr("10.0.0.1"),
		WithAllowedPrefixes(netip.MustParsePrefix("10.0.0.0/8")),
	))

	require.ErrorContains(t, CheckAddr(netip.Addr{}), "invalid address")

	// NAT64 translation forms report the decoded embedded destination,
	// keeping the requested address in Host.
	err = CheckAddr(netip.MustParseAddr("64:ff9b::a00:1"))
	require.ErrorAs(t, err, &blockedErr)
	require.Equal(t, "64:ff9b::a00:1", blockedErr.Host)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), blockedErr.Addr)
	require.ErrorContains(t, err, "10.0.0.1 is in a private or reserved range")
}

func TestIsBlockedAddrFailsClosedOnInvalid(t *testing.T) {
	t.Parallel()

	// The zero Addr matches no classification predicate or prefix; it
	// must be blocked, not approved, even when an allowlist exists.
	require.True(t, newConfig(nil).isBlockedAddr(netip.Addr{}))
	cfg := newConfig([]Option{WithAllowedPrefixes(netip.MustParsePrefix("0.0.0.0/0"))})
	require.True(t, cfg.isBlockedAddr(netip.Addr{}))
}

func TestParseAllowedPrefix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		raw        string
		wantPrefix string
		addr       string
		wantErr    string
	}{
		{
			name:       "MappedIPv4Address",
			raw:        "::ffff:127.0.0.1/128",
			wantPrefix: "127.0.0.1/32",
			addr:       "127.0.0.1",
		},
		{
			name:       "MappedIPv4Network",
			raw:        "::ffff:10.0.0.0/104",
			wantPrefix: "10.0.0.0/8",
			addr:       "10.23.45.67",
		},
		{
			name:    "MappedPrefixTooShort",
			raw:     "::ffff:0.0.0.0/95",
			wantErr: "IPv4-mapped IPv6 prefix length must be at least 96 bits",
		},
		{
			name:       "IPv4Unchanged",
			raw:        "127.0.0.0/8",
			wantPrefix: "127.0.0.0/8",
			addr:       "127.0.0.1",
		},
		{
			name:       "IPv6Unchanged",
			raw:        "::1/128",
			wantPrefix: "::1/128",
			addr:       "::1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prefix, err := ParseAllowedPrefix(tc.raw)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, netip.MustParsePrefix(tc.wantPrefix), prefix)
			cfg := newConfig([]Option{WithAllowedPrefixes(prefix)})
			require.False(t, cfg.isBlockedAddr(netip.MustParseAddr(tc.addr)))
		})
	}
}

func TestParseNAT64Prefix(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"2001:db8::/32",
		"2001:db8:100::/40",
		"2001:db8:122::/48",
		"2001:db8:122:300::/56",
		"2001:db8:122:344::/64",
		"64:ff9b:1:2:3:4::/96",
	} {
		prefix, err := ParseNAT64Prefix(raw)
		require.NoError(t, err, raw)
		require.Equal(t, netip.MustParsePrefix(raw), prefix)
	}

	for _, raw := range []string{"64:ff9b::/95", "64:ff9b::/97", "2001:db8::/24", "2001:db8::/128", "10.0.0.0/8", "::ffff:0.0.0.0/96", "garbage"} {
		_, err := ParseNAT64Prefix(raw)
		require.Error(t, err, raw)
	}

	require.Panics(t, func() {
		WithNAT64Prefixes(netip.MustParsePrefix("10.0.0.0/8"))
	})
}

func startCanaryServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	var hits atomic.Int64
	canary := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	_ = canary.Listener.Close()
	canary.Listener = ln
	canary.Start()
	t.Cleanup(canary.Close)
	return canary, &hits
}

var allowOnly127001 = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

func TestCheckSameOriginRedirect(t *testing.T) {
	t.Parallel()

	req := func(method, rawURL string) *http.Request {
		u, err := url.Parse(rawURL)
		require.NoError(t, err)
		return &http.Request{Method: method, URL: u}
	}

	origin := "https://provider.example/revoke"
	cases := []struct {
		name    string
		req     *http.Request
		origin  string
		wantErr string
	}{
		{name: "SameOrigin", req: req(http.MethodPost, "https://provider.example/revoke2")},
		{name: "ExplicitDefaultPort", req: req(http.MethodPost, "https://provider.example:443/revoke2")},
		{name: "DifferentPort", req: req(http.MethodPost, "https://provider.example:8443/collect"), wantErr: "must stay on origin"},
		{name: "DifferentHost", req: req(http.MethodPost, "https://attacker.example/collect"), wantErr: "must stay on origin"},
		{name: "MethodChanged", req: req(http.MethodGet, "https://provider.example/other"), wantErr: "changed method"},
		{name: "ProtocolDowngrade", req: req(http.MethodPost, "http://provider.example/revoke"), wantErr: "must stay on origin"},
		{
			name:    "DifferentLoopbackOrigin",
			req:     req(http.MethodPost, "http://127.0.0.1:9999/revoke"),
			origin:  "http://localhost:1234/revoke",
			wantErr: "must stay on origin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := tc.origin
			if o == "" {
				o = origin
			}
			err := CheckSameOriginRedirect(tc.req, []*http.Request{req(http.MethodPost, o)})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestDialAttemptDeadline(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 18, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name              string
		timeRemaining     time.Duration
		attemptsRemaining int
		want              time.Duration
	}{
		{name: "FirstOfTwo", timeRemaining: 6 * time.Second, attemptsRemaining: 2, want: 3 * time.Second},
		{name: "FirstOfThree", timeRemaining: 6 * time.Second, attemptsRemaining: 3, want: 2 * time.Second},
		{name: "LastAttempt", timeRemaining: 6 * time.Second, attemptsRemaining: 1, want: 6 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deadline := now.Add(tc.timeRemaining)
			require.Equal(t, now.Add(tc.want), dialAttemptDeadline(now, deadline, tc.attemptsRemaining))
		})
	}
}

func TestDialValidatedIPs(t *testing.T) {
	t.Parallel()

	t.Run("PartialDeadlineAllowsLaterAddress", func(t *testing.T) {
		t.Parallel()

		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, listener.Close())
		})
		_, port, err := net.SplitHostPort(listener.Addr().String())
		require.NoError(t, err)

		accepted := make(chan net.Conn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- conn
		}()

		stalledIP := netip.MustParseAddr("127.0.0.2")
		dialer := &net.Dialer{
			ControlContext: func(ctx context.Context, _, addr string, _ syscall.RawConn) error {
				if addr != net.JoinHostPort(stalledIP.String(), port) {
					return nil
				}
				<-ctx.Done()
				return ctx.Err()
			},
		}
		ctx := testContext(t, 2*time.Second)
		conn, err := dialValidatedIPs(ctx, dialer, "tcp4", port, []netip.Addr{
			stalledIP,
			netip.MustParseAddr("127.0.0.1"),
		})
		require.NoError(t, err)
		require.NoError(t, conn.Close())

		select {
		case serverConn := <-accepted:
			require.NoError(t, serverConn.Close())
		case err := <-acceptErr:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal("timed out waiting for the successful connection")
		}
	})

	v6 := netip.MustParseAddr("2001:db8::1")
	v4 := netip.MustParseAddr("192.0.2.1")
	isV6 := func(addr string) bool { return strings.HasPrefix(addr, "[") }

	t.Run("FallbackFamilyWinsWhilePrimaryStalls", func(t *testing.T) {
		t.Parallel()

		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		dialer := dialContextFunc(func(ctx context.Context, _, addr string) (net.Conn, error) {
			if isV6(addr) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return client, nil
		})

		ctx := testContext(t, testWait)
		start := time.Now()
		conn, err := dialValidatedIPs(ctx, dialer, "tcp", "80", []netip.Addr{v6, v4})
		elapsed := time.Since(start)
		require.NoError(t, err)
		require.Same(t, client, conn)
		// Serial dialing would burn the stalled primary's share of the
		// deadline (half of testWait) before trying the other family;
		// the fallback race must connect much sooner.
		require.Less(t, elapsed, testWait/2-time.Second)
	})

	t.Run("PrimaryFailureStartsFallbackImmediately", func(t *testing.T) {
		t.Parallel()

		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		dialer := dialContextFunc(func(_ context.Context, _, addr string) (net.Conn, error) {
			if isV6(addr) {
				return nil, errors.New("v6 refused")
			}
			return client, nil
		})

		ctx := testContext(t, testWait)
		start := time.Now()
		conn, err := dialValidatedIPs(ctx, dialer, "tcp", "80", []netip.Addr{v6, v4})
		elapsed := time.Since(start)
		require.NoError(t, err)
		require.Same(t, client, conn)
		// The fallback must start as soon as every primary attempt has
		// failed rather than waiting out the fallback delay.
		require.Less(t, elapsed, defaultFallbackDelay)
	})

	t.Run("PrimaryErrorReportedWhenBothFail", func(t *testing.T) {
		t.Parallel()

		errV6 := errors.New("v6 refused")
		errV4 := errors.New("v4 refused")
		dialer := dialContextFunc(func(_ context.Context, _, addr string) (net.Conn, error) {
			if isV6(addr) {
				return nil, errV6
			}
			return nil, errV4
		})

		ctx := testContext(t, testWait)
		conn, err := dialValidatedIPs(ctx, dialer, "tcp", "80", []netip.Addr{v6, v4})
		require.Nil(t, conn)
		require.ErrorIs(t, err, errV6)
	})

	t.Run("LosingDialIsClosed", func(t *testing.T) {
		t.Parallel()

		winner, winnerPeer := net.Pipe()
		loserInner, loserPeer := net.Pipe()
		t.Cleanup(func() {
			_ = winner.Close()
			_ = winnerPeer.Close()
			_ = loserInner.Close()
			_ = loserPeer.Close()
		})
		loser := newCloseNotifyConn(loserInner)
		dialer := dialContextFunc(func(_ context.Context, _, addr string) (net.Conn, error) {
			if isV6(addr) {
				// Ignore cancellation deliberately and complete long
				// after the fallback has won, exercising the
				// loser-cleanup path.
				time.Sleep(2 * time.Second)
				return loser, nil
			}
			return winner, nil
		})

		ctx := testContext(t, testWait)
		conn, err := dialValidatedIPs(ctx, dialer, "tcp", "80", []netip.Addr{v6, v4})
		require.NoError(t, err)
		require.Same(t, winner, conn)
		select {
		case <-loser.closed:
		case <-ctx.Done():
			t.Fatal("losing dial's connection was not closed")
		}
	})

	t.Run("NegativeFallbackDelayDialsSequentially", func(t *testing.T) {
		t.Parallel()

		var mu sync.Mutex
		inFlight, maxInFlight := 0, 0
		dialer := &net.Dialer{
			FallbackDelay: -1,
			ControlContext: func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
				mu.Lock()
				inFlight++
				if inFlight > maxInFlight {
					maxInFlight = inFlight
				}
				mu.Unlock()
				<-ctx.Done()
				mu.Lock()
				inFlight--
				mu.Unlock()
				return ctx.Err()
			},
		}

		// Both attempts stall until their share of the deadline ends. A
		// (wrongly) racing fallback would overlap the stalled primary.
		ctx := testContext(t, 1500*time.Millisecond)
		conn, err := dialValidatedIPs(ctx, dialer, "tcp", "9", []netip.Addr{
			netip.MustParseAddr("::1"),
			netip.MustParseAddr("127.0.0.1"),
		})
		require.Nil(t, conn)
		require.Error(t, err)
		mu.Lock()
		defer mu.Unlock()
		require.Equal(t, 1, maxInFlight)
	})
}

func TestFallbackDelayResolution(t *testing.T) {
	t.Parallel()

	require.Equal(t, defaultFallbackDelay, fallbackDelay(dialContextFunc(nil)))
	require.Equal(t, defaultFallbackDelay, fallbackDelay(&net.Dialer{}))
	require.Equal(t, 150*time.Millisecond, fallbackDelay(&net.Dialer{FallbackDelay: 150 * time.Millisecond}))
	require.Equal(t, time.Duration(-1), fallbackDelay(&net.Dialer{FallbackDelay: -5 * time.Millisecond}))
}

func TestPartitionByFamily(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr
	primaries, fallbacks := partitionByFamily([]netip.Addr{
		addr("2001:db8::1"), addr("8.8.8.8"), addr("2001:db8::2"), addr("::ffff:8.8.4.4"),
	})
	require.Equal(t, []netip.Addr{addr("2001:db8::1"), addr("2001:db8::2")}, primaries)
	// Mapped IPv4 counts as IPv4, and order is preserved.
	require.Equal(t, []netip.Addr{addr("8.8.8.8"), addr("::ffff:8.8.4.4")}, fallbacks)

	// The resolver's first answer picks the primary family.
	primaries, fallbacks = partitionByFamily([]netip.Addr{addr("::ffff:8.8.4.4"), addr("2001:db8::1")})
	require.Equal(t, []netip.Addr{addr("::ffff:8.8.4.4")}, primaries)
	require.Equal(t, []netip.Addr{addr("2001:db8::1")}, fallbacks)

	primaries, fallbacks = partitionByFamily([]netip.Addr{addr("8.8.8.8"), addr("8.8.4.4")})
	require.Equal(t, []netip.Addr{addr("8.8.8.8"), addr("8.8.4.4")}, primaries)
	require.Empty(t, fallbacks)

	primaries, fallbacks = partitionByFamily(nil)
	require.Empty(t, primaries)
	require.Empty(t, fallbacks)
}

func TestDialContextIPv6Zone(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("http://[fe80::1%25eth0]:80")
	require.NoError(t, err)
	literalAddr := u.Host
	errDial := errors.New("dial stopped")
	cases := []struct {
		name        string
		allowed     []netip.Prefix
		wantBlocked bool
		wantAddr    string
	}{
		{name: "BlockedByDefault", wantBlocked: true},
		{
			name:     "AllowedPreservesZone",
			allowed:  []netip.Prefix{netip.MustParsePrefix("fe80::/10")},
			wantAddr: literalAddr,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var dialedAddr string
			dialer := dialContextFunc(func(_ context.Context, network, addr string) (net.Conn, error) {
				require.Equal(t, "tcp6", network)
				dialedAddr = addr
				return nil, errDial
			})
			dial := NewDialContext(dialer, WithAllowedPrefixes(tc.allowed...))
			conn, err := dial(t.Context(), "tcp6", literalAddr)
			require.Nil(t, conn)
			if tc.wantBlocked {
				var blockedErr *BlockedError
				require.ErrorAs(t, err, &blockedErr)
				require.Empty(t, dialedAddr)
				return
			}
			require.ErrorIs(t, err, errDial)
			require.Equal(t, tc.wantAddr, dialedAddr)
		})
	}
}

func TestDefaultDialerMirrorsDefaultTransport(t *testing.T) {
	t.Parallel()

	dialer := defaultDialer()
	require.Equal(t, 30*time.Second, dialer.Timeout)
	require.Equal(t, 30*time.Second, dialer.KeepAlive)
}

func TestWithDefaultTimeout(t *testing.T) {
	t.Parallel()

	t.Run("InjectsDeadlineWhenAbsent", func(t *testing.T) {
		t.Parallel()

		var got time.Time
		dial := withDefaultTimeout(func(ctx context.Context, _, _ string) (net.Conn, error) {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			got = deadline
			return nil, nil
		})
		before := time.Now()
		_, err := dial(context.Background(), "tcp", "192.0.2.1:80")
		require.NoError(t, err)
		require.WithinRange(t, got, before, before.Add(defaultDialTimeout+time.Minute))
	})

	t.Run("PreservesSoonerCallerDeadline", func(t *testing.T) {
		t.Parallel()

		want := time.Now().Add(time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), want)
		defer cancel()
		dial := withDefaultTimeout(func(ctx context.Context, _, _ string) (net.Conn, error) {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.Equal(t, want, deadline)
			return nil, nil
		})
		_, err := dial(ctx, "tcp", "192.0.2.1:80")
		require.NoError(t, err)
	})

	t.Run("CapsLaterCallerDeadline", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
		defer cancel()
		var got time.Time
		dial := withDefaultTimeout(func(ctx context.Context, _, _ string) (net.Conn, error) {
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			got = deadline
			return nil, nil
		})
		before := time.Now()
		_, err := dial(ctx, "tcp", "192.0.2.1:80")
		require.NoError(t, err)
		require.WithinRange(t, got, before, before.Add(defaultDialTimeout+time.Minute))
	})
}

func TestDialContextNetworkRestriction(t *testing.T) {
	t.Parallel()

	dial := NewDialContext(dialContextFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialer must not be reached")
		return nil, nil
	}))
	for _, network := range []string{"udp", "udp4", "unix", "ip"} {
		conn, err := dial(t.Context(), network, "8.8.8.8:53")
		require.Nil(t, conn)
		require.ErrorContains(t, err, "not allowed")
	}
}

func TestNewHTTPClientTimeout(t *testing.T) {
	t.Parallel()

	require.Zero(t, NewHTTPClient(&http.Client{}).Timeout)
	require.Equal(t, 30*time.Second, NewHTTPClient(nil).Timeout)
	require.Equal(t, 5*time.Second, NewHTTPClient(&http.Client{Timeout: 5 * time.Second}).Timeout)
}

func TestNewHTTPClientPreservesJar(t *testing.T) {
	t.Parallel()

	require.Nil(t, NewHTTPClient(nil).Jar)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	require.Same(t, jar, NewHTTPClient(&http.Client{Jar: jar}).Jar)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewHTTPClientRejectsUnguardableTransport(t *testing.T) {
	t.Parallel()

	base := &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("must not be reached")
		}),
	}
	require.PanicsWithValue(t,
		"safedial: base transport safedial.roundTripperFunc cannot be guarded: only nil or *http.Transport is supported",
		func() { NewHTTPClient(base) },
	)
}

// Mutates the global http.DefaultTransport, so it must not run in parallel
// with tests that construct guarded clients from a nil base.
//
//nolint:paralleltest
func TestRejectsUnguardableDefaultTransport(t *testing.T) {
	orig := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("must not be reached")
	})
	defer func() { http.DefaultTransport = orig }()

	want := "safedial: http.DefaultTransport safedial.roundTripperFunc cannot be guarded: only *http.Transport is supported"
	require.PanicsWithValue(t, want, func() { NewTransport(nil) })
	require.PanicsWithValue(t, want, func() { NewHTTPClient(nil) })
	require.PanicsWithValue(t, want, func() { NewHTTPClient(&http.Client{}) })
}

func TestNewTransportPreservesSettings(t *testing.T) {
	t.Parallel()

	base := &http.Transport{
		MaxIdleConns:          42,
		ResponseHeaderTimeout: 7 * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
	}
	transport := NewTransport(base)
	require.Equal(t, 42, transport.MaxIdleConns)
	require.Equal(t, 7*time.Second, transport.ResponseHeaderTimeout)
	require.Nil(t, transport.Proxy)
	require.Nil(t, transport.DialTLSContext)
	require.NotNil(t, transport.DialContext)
	// The base transport is not mutated.
	require.NotNil(t, base.Proxy)
}

func TestNewTransportSeversInheritedTLSNextProto(t *testing.T) {
	t.Parallel()

	upgrade := func(string, *tls.Conn) http.RoundTripper { return nil }

	t.Run("H2EntryDropsPoolAndKeepsHTTP2", func(t *testing.T) {
		t.Parallel()

		base := &http.Transport{
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
				"h2": upgrade,
			},
		}
		transport := NewTransport(base)
		require.Nil(t, transport.TLSNextProto)
		require.True(t, transport.ForceAttemptHTTP2)
		// The base transport is not mutated.
		require.Contains(t, base.TLSNextProto, "h2")
		require.False(t, base.ForceAttemptHTTP2)
	})

	t.Run("ExoticEntryDroppedWithoutEnablingHTTP2", func(t *testing.T) {
		t.Parallel()

		base := &http.Transport{
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
				"custom-proto": upgrade,
			},
		}
		transport := NewTransport(base)
		require.NotNil(t, transport.TLSNextProto)
		require.Empty(t, transport.TLSNextProto)
		require.False(t, transport.ForceAttemptHTTP2)
	})

	t.Run("ExplicitlyEmptyMapStaysDisabled", func(t *testing.T) {
		t.Parallel()

		base := &http.Transport{
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
			ForceAttemptHTTP2: true,
		}
		transport := NewTransport(base)
		require.NotNil(t, transport.TLSNextProto)
		require.Empty(t, transport.TLSNextProto)
	})
}

func TestNewHTTPClientPreservesCheckRedirect(t *testing.T) {
	t.Parallel()

	// A redirecting server and its target, both on the allowlisted
	// loopback so only redirect handling decides the outcome.
	newRedirectingServer := func(t *testing.T) (*httptest.Server, *atomic.Int64) {
		t.Helper()
		var finalHits atomic.Int64
		mux := http.NewServeMux()
		mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/final", http.StatusFound)
		})
		mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) {
			finalHits.Add(1)
			w.WriteHeader(http.StatusOK)
		})
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)
		return server, &finalHits
	}

	t.Run("ErrUseLastResponseStopsFollowing", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		server, finalHits := newRedirectingServer(t)

		base := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/start", nil)
		require.NoError(t, err)
		resp, err := NewHTTPClient(base, WithAllowedPrefixes(allowOnly127001...)).Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		require.Zero(t, finalHits.Load())
	})

	t.Run("BaseErrorStopsFollowing", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		server, finalHits := newRedirectingServer(t)

		errBase := errors.New("base says no")
		base := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errBase
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/start", nil)
		require.NoError(t, err)
		resp, err := NewHTTPClient(base, WithAllowedPrefixes(allowOnly127001...)).Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.ErrorIs(t, err, errBase)
		require.Zero(t, finalHits.Load())
	})

	t.Run("GuardStillChecksRedirectsBaseAllows", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		canary, hits := startCanaryServer(t)
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, canary.URL, http.StatusFound)
		}))
		t.Cleanup(attacker.Close)

		var baseChecks atomic.Int64
		base := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				baseChecks.Add(1)
				return nil
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, attacker.URL, nil)
		require.NoError(t, err)
		resp, err := NewHTTPClient(base, WithAllowedPrefixes(allowOnly127001...)).Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		var blockedErr *BlockedError
		require.ErrorAs(t, err, &blockedErr)
		require.Equal(t, int64(1), baseChecks.Load())
		require.Zero(t, hits.Load())
	})
}

func TestGuardedClientSpeaksHTTP2(t *testing.T) {
	t.Parallel()

	newH2Server := func(t *testing.T) *httptest.Server {
		t.Helper()
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		server.EnableHTTP2 = true
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}

	t.Run("PreconfiguredH2Base", func(t *testing.T) {
		t.Parallel()

		server := newH2Server(t)
		ctx := testContext(t, testWait)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		client := NewHTTPClient(server.Client(), WithAllowedPrefixes(allowOnly127001...))
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, 2, resp.ProtoMajor)
	})

	// A plain, never-configured base is the dangerous case: cloning it
	// fires the base's protocol setup, which leaves the clone's TLS
	// config advertising "h2" via ALPN while the guarded DialContext
	// stops the stdlib from wiring HTTP/2 up on the clone by itself.
	// Without realignment, this request fails with a malformed-response
	// error instead of negotiating HTTP/2.
	t.Run("PlainBase", func(t *testing.T) {
		t.Parallel()

		server := newH2Server(t)
		transport := NewTransport(&http.Transport{}, WithAllowedPrefixes(allowOnly127001...))
		require.NotNil(t, transport.TLSClientConfig)
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		transport.TLSClientConfig.RootCAs = pool

		ctx := testContext(t, testWait)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		client := &http.Client{Transport: transport}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, 2, resp.ProtoMajor)
	})
}

// A guarded transport must never advertise an ALPN protocol it cannot
// speak: whenever the TLS config offers "h2", either an upgrade entry or
// ForceAttemptHTTP2 must be in place.
func TestNewTransportALPNConsistency(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		base *http.Transport
	}{
		{name: "PlainBase", base: &http.Transport{}},
		{name: "PlainBaseWithSettings", base: &http.Transport{MaxIdleConns: 42}},
		{
			name: "H2AdvertisingTLSConfigOnly",
			base: &http.Transport{
				TLSClientConfig: &tls.Config{NextProtos: []string{"h2", "http/1.1"}},
			},
		},
		{name: "CustomTLSConfigNoALPN", base: &http.Transport{TLSClientConfig: &tls.Config{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			transport := NewTransport(tc.base)
			advertisesH2 := transport.TLSClientConfig != nil &&
				slices.Contains(transport.TLSClientConfig.NextProtos, "h2")
			if advertisesH2 {
				_, hasUpgrade := transport.TLSNextProto["h2"]
				require.True(t, transport.ForceAttemptHTTP2 || hasUpgrade,
					"transport advertises h2 via ALPN but cannot speak it")
			}
		})
	}
}

func TestHTTPClientSSRF(t *testing.T) {
	t.Parallel()

	t.Run("BlocksLoopback", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		var hits atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		resp, err := NewHTTPClient(nil).Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, err)
		var blockedErr *BlockedError
		require.ErrorAs(t, err, &blockedErr)
		require.Zero(t, hits.Load())
	})

	t.Run("DeprecatedSiteLocalIPv6", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name        string
			allowed     []netip.Prefix
			wantBlocked bool
		}{
			{name: "Blocked", wantBlocked: true},
			{
				name:    "AllowedPrefixOverride",
				allowed: []netip.Prefix{netip.MustParsePrefix("fec0::/10")},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				ctx := testContext(t, testWait)
				if !tc.wantBlocked {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				client := NewHTTPClient(nil, WithAllowedPrefixes(tc.allowed...))
				transport, ok := client.Transport.(*http.Transport)
				require.True(t, ok)
				conn, err := transport.DialContext(ctx, "tcp6", "[fec0::1]:80")
				if conn != nil {
					require.NoError(t, conn.Close())
				}
				if tc.wantBlocked {
					var blockedErr *BlockedError
					require.ErrorAs(t, err, &blockedErr)
					return
				}
				require.ErrorIs(t, err, context.Canceled)
				require.NotContains(t, err.Error(), "not allowed by policy")
			})
		}
	})

	t.Run("BlocksHostnameResolvingToLoopback", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		var hits atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)
		_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:"+port, nil)
		require.NoError(t, err)
		resp, err := NewHTTPClient(nil).Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, err)
		require.Zero(t, hits.Load())
	})

	t.Run("BlocksRedirectToLoopback", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		canary, hits := startCanaryServer(t)
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, canary.URL, http.StatusFound)
		}))
		t.Cleanup(attacker.Close)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, attacker.URL, nil)
		require.NoError(t, err)
		resp, err := NewHTTPClient(nil, WithAllowedPrefixes(allowOnly127001...)).Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, err)
		var blockedErr *BlockedError
		require.ErrorAs(t, err, &blockedErr)
		// Host is the host portion only, without the port.
		require.Equal(t, "127.0.0.2", blockedErr.Host)
		require.Equal(t, netip.MustParseAddr("127.0.0.2"), blockedErr.Addr)
		require.Zero(t, hits.Load())
	})

	t.Run("BlocksPostRedirectToLoopback", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		canary, hits := startCanaryServer(t)
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, canary.URL, http.StatusTemporaryRedirect)
		}))
		t.Cleanup(attacker.Close)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, attacker.URL, strings.NewReader("secret"))
		require.NoError(t, err)
		resp, err := NewHTTPClient(nil, WithAllowedPrefixes(allowOnly127001...)).Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, err)
		require.Zero(t, hits.Load())
	})

	t.Run("BlocksRedirectToMetadataIP", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		}))
		t.Cleanup(attacker.Close)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, attacker.URL, nil)
		require.NoError(t, err)
		resp, err := NewHTTPClient(nil, WithAllowedPrefixes(allowOnly127001...)).Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, err)
	})

	t.Run("AllowsAllowlistedLoopback", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(server.Close)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		resp, err := NewHTTPClient(nil, WithAllowedPrefixes(allowOnly127001...)).Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
	})
}

func TestRedirectPolicies(t *testing.T) {
	t.Parallel()

	// Both servers listen on the allowlisted loopback so only the
	// redirect policy decides the outcome.
	newTarget := func(t *testing.T) (*httptest.Server, *atomic.Int64) {
		t.Helper()
		var hits atomic.Int64
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(target.Close)
		return target, &hits
	}

	t.Run("DenyBlocksAnyRedirect", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		target, hits := newTarget(t)
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		t.Cleanup(source.Close)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
		require.NoError(t, err)
		client := NewHTTPClient(nil,
			WithAllowedPrefixes(allowOnly127001...),
			WithRedirectPolicy(RedirectDeny),
		)
		resp, err := client.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.ErrorContains(t, err, "redirects are not allowed")
		require.Zero(t, hits.Load())
	})

	t.Run("SameOriginBlocksCrossOrigin", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		target, hits := newTarget(t)
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// target runs on a different port, so a different origin.
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		t.Cleanup(source.Close)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
		require.NoError(t, err)
		client := NewHTTPClient(nil,
			WithAllowedPrefixes(allowOnly127001...),
			WithRedirectPolicy(RedirectSameOrigin),
		)
		resp, err := client.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.ErrorContains(t, err, "must stay on origin")
		require.Zero(t, hits.Load())
	})

	t.Run("SameOriginFollowsWithinOrigin", func(t *testing.T) {
		t.Parallel()
		ctx := testContext(t, testWait)
		var finalHits atomic.Int64
		mux := http.NewServeMux()
		mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/final", http.StatusFound)
		})
		mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) {
			finalHits.Add(1)
			w.WriteHeader(http.StatusOK)
		})
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/start", nil)
		require.NoError(t, err)
		client := NewHTTPClient(nil,
			WithAllowedPrefixes(allowOnly127001...),
			WithRedirectPolicy(RedirectSameOrigin),
		)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, int64(1), finalHits.Load())
	})
}
