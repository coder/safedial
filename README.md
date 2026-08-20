# safedial

[![Go Reference](https://pkg.go.dev/badge/github.com/coder/safedial.svg)](https://pkg.go.dev/github.com/coder/safedial)

SSRF-hardened dialers and HTTP clients for Go services that connect to
destinations influenced by someone other than the service operator: URLs
submitted by end users, org-admin-configured integrations, webhook
subscriptions, OAuth/OIDC discovery documents, MCP servers, and similar.

Without a guard, any of those can point a server at `169.254.169.254`, a
loopback admin API, or an internal service, and the server will connect with
its own network position and credentials.

## What it does

- **Blocks private and special-use destinations by default.** Loopback,
  RFC 1918, link-local (including cloud metadata), CGNAT, multicast,
  unspecified, documentation, benchmarking, and the IPv6 special-use ranges
  the standard library does not classify.
- **Prevents DNS rebinding.** Hostnames are resolved once, every resolved
  address is validated, and the connection goes to a validated IP directly.
  A resolver that answers with any blocked address fails the whole dial
  rather than racing it. TLS verification still uses the hostname.
- **Decodes NAT64.** Addresses under the RFC 6052 well-known prefix
  `64:ff9b::/96` (and operator-declared RFC 8215 prefixes) have their
  embedded IPv4 destination extracted and validated with the full IPv4
  policy, so a translator is not a side door to blocked targets.
- **Normalizes address forms.** IPv4-mapped IPv6 addresses are unmapped and
  IPv6 zones are stripped before policy checks, so `::ffff:10.0.0.1` cannot
  bypass a `10.0.0.0/8` block.
- **Controls redirects.** Blocked IP literals are rejected before a request
  is attempted, every hop goes through the guarded dialer, and stricter
  policies (same-origin only, deny all) are available for credentialed
  flows such as OAuth token exchange.
- **Hardens the transport.** Proxies, alternate dial paths, and TLS
  protocol upgrades inherited from the base transport (which share
  connection pools with the unguarded base) are cleared so the guarded
  dialer is the only way out; HTTP/2 stays enabled through the standard
  library's own implementation.
- **Supports explicit allowlists.** Deployments that legitimately need to
  reach internal destinations opt in per CIDR; allowed prefixes take
  precedence over every block rule.
- **Splits dial deadlines, keeps Happy Eyeballs.** The remaining deadline
  is divided across resolved addresses so one black-holed address cannot
  consume the whole budget, and dual-stack destinations keep net.Dialer's
  address-family fallback race so a broken family does not stall the dial.

## Usage

```go
import "github.com/coder/safedial"

// HTTP client for user-controlled URLs.
client := safedial.NewHTTPClient(nil)

// Inherit timeouts and transport settings from an existing client, allow a
// deployment-configured internal range, and keep OAuth redirects on-origin.
allowed, err := safedial.ParseAllowedPrefix("10.2.0.0/16")
if err != nil {
    // Reject the configuration.
}
client = safedial.NewHTTPClient(base,
    safedial.WithAllowedPrefixes(allowed),
    safedial.WithRedirectPolicy(safedial.RedirectSameOrigin),
)

// Raw guarded dialer for non-HTTP protocols or hand-built transports.
dial := safedial.NewDialContext(nil)

// Map policy rejections to caller-facing validation errors.
var blocked *safedial.BlockedError
if errors.As(err, &blocked) {
    // 400, not 502: the destination was rejected, nothing was dialed.
}
```

## What it does not do

- **It does not protect operator-controlled destinations.** A deployment
  operator's own OIDC issuer, SMTP smarthost, or telemetry endpoint often
  legitimately lives on an internal address, and the operator already
  controls the process. Wrapping those breaks real deployments without
  crossing a trust boundary.
- **It does not filter by port, scheme, or hostname.** Policy is applied to
  resolved IP addresses. Validate URLs and schemes before making requests.
- **It does not sandbox the response.** What the caller does with fetched
  bytes is out of scope.

## Stability

The address policy (which ranges are blocked) may gain new special-use
ranges in minor releases; treat additions as hardening, not breaking
changes. The Go API follows semver.
