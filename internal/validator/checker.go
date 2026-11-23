package validator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/netpolicy"
	"github.com/tatlilimon/proxier/internal/socks4"
	"golang.org/x/net/proxy"
)

// Reason classifies the outcome of a check.
type Reason string

const (
	ReasonOK                  Reason = ""
	ReasonUnsupportedProtocol Reason = "unsupported_protocol"
	ReasonDisallowedAddress   Reason = "disallowed_address"
	ReasonConnect             Reason = "connect_failed"
	ReasonTimeout             Reason = "timeout"
	ReasonTLS                 Reason = "tls_error"
	ReasonStatus              Reason = "bad_status"
	ReasonRedirect            Reason = "redirect"
	ReasonInvalidResponse     Reason = "invalid_probe_response"
	ReasonLeak                Reason = "leaks_client_ip"
	// ReasonRoutingUnverified: the proxy answered correctly, but the
	// client's own address is not known yet, so leakage cannot be ruled out.
	ReasonRoutingUnverified Reason = "routing_unverified"
	// ReasonCanceled: the check was interrupted (shutdown). Not a failure.
	ReasonCanceled Reason = "canceled"
)

// FailureReasons lists every reason that counts as a failed check.
var FailureReasons = []Reason{
	ReasonUnsupportedProtocol, ReasonDisallowedAddress, ReasonConnect, ReasonTimeout,
	ReasonTLS, ReasonStatus, ReasonRedirect, ReasonInvalidResponse, ReasonLeak,
}

// maxProbeBody bounds the probe response that is read and parsed.
const maxProbeBody = 64 << 10

// Result is the outcome of one check. Exactly one of OK and Indeterminate is
// true, or neither for a failure (with Reason set).
type Result struct {
	OK            bool
	Indeterminate bool
	Reason        Reason
	Detail        string
	Latency       time.Duration
	Origins       []string
}

// CheckerConfig configures a Checker.
type CheckerConfig struct {
	Timeout      time.Duration
	ProbeURL     string
	RootCAs      *x509.CertPool // nil: system roots
	AllowPrivate bool
	UserAgent    string
}

// Checker tests one proxy against the probe URL. It has no side effects on
// the pool: background validation and POST /validate share it, so both give
// the same answer for the same proxy.
//
// A proxy passes only if every step holds: the connection (and, for HTTPS
// probes or HTTPS proxies, a verified TLS handshake) succeeds; the probe
// answers 2xx without a redirect; the body is a bounded JSON document whose
// origin field lists valid IP addresses; and none of them is the client's
// own address (the routing baseline).
type Checker struct {
	timeout      time.Duration
	probeURL     string
	tlsConfig    *tls.Config
	allowPrivate bool
	userAgent    string
	baseline     *Baseline
}

// NewChecker validates cfg and returns a Checker.
func NewChecker(cfg CheckerConfig) (*Checker, error) {
	u, err := url.Parse(cfg.ProbeURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("probe URL %q must be an http or https URL with a host", cfg.ProbeURL)
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("check timeout must be positive")
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = "proxier"
	}
	return &Checker{
		timeout:      cfg.Timeout,
		probeURL:     cfg.ProbeURL,
		tlsConfig:    &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		allowPrivate: cfg.AllowPrivate,
		userAgent:    ua,
		baseline:     &Baseline{},
	}, nil
}

// Baseline returns the routing baseline used for leak detection.
func (c *Checker) Baseline() *Baseline { return c.baseline }

// Timeout returns the per-check timeout.
func (c *Checker) Timeout() time.Duration { return c.timeout }

// Check tests p. Cancelling parent yields an Indeterminate, ReasonCanceled
// result rather than a failure.
func (c *Checker) Check(parent context.Context, p models.Proxy) Result {
	if !p.Protocol.Valid() {
		return Result{Reason: ReasonUnsupportedProtocol, Detail: fmt.Sprintf("protocol %q", p.Protocol)}
	}
	if err := netpolicy.CheckHost(p.Host, c.allowPrivate); err != nil {
		return Result{Reason: ReasonDisallowedAddress, Detail: err.Error()}
	}

	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()

	transport, err := c.transport(p)
	if err != nil {
		return Result{Reason: ReasonConnect, Detail: err.Error()}
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.probeURL, nil)
	if err != nil {
		return Result{Reason: ReasonConnect, Detail: err.Error()}
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		if parent.Err() != nil {
			return Result{Indeterminate: true, Reason: ReasonCanceled}
		}
		return Result{Reason: classify(ctx, err), Detail: err.Error(), Latency: latency}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return Result{Reason: ReasonRedirect, Detail: fmt.Sprintf("status %d to %q", resp.StatusCode, resp.Header.Get("Location")), Latency: latency}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return Result{Reason: ReasonStatus, Detail: fmt.Sprintf("status %d", resp.StatusCode), Latency: latency}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody+1))
	if err != nil {
		if parent.Err() != nil {
			return Result{Indeterminate: true, Reason: ReasonCanceled}
		}
		return Result{Reason: classify(ctx, err), Detail: err.Error(), Latency: latency}
	}
	if len(body) > maxProbeBody {
		return Result{Reason: ReasonInvalidResponse, Detail: "probe response too large", Latency: latency}
	}
	origins, err := ParseOrigins(body)
	if err != nil {
		return Result{Reason: ReasonInvalidResponse, Detail: err.Error(), Latency: latency}
	}

	known, leak := c.baseline.Leaks(origins)
	switch {
	case leak:
		return Result{Reason: ReasonLeak, Detail: "probe saw the client's own address", Latency: latency, Origins: origins}
	case !known:
		return Result{Indeterminate: true, Reason: ReasonRoutingUnverified, Latency: latency, Origins: origins}
	}
	return Result{OK: true, Latency: latency, Origins: origins}
}

// transport builds a single-use transport that routes through p.
func (c *Checker) transport(p models.Proxy) (*http.Transport, error) {
	dialer := &net.Dialer{Timeout: c.timeout, Control: netpolicy.Control(c.allowPrivate)}
	tr := &http.Transport{
		TLSClientConfig:        c.tlsConfig.Clone(),
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    c.timeout,
		ResponseHeaderTimeout:  c.timeout,
		MaxResponseHeaderBytes: 64 << 10,
	}

	switch p.Protocol {
	case models.ProtoHTTP, models.ProtoHTTPS:
		// For an https proxy the connection to the proxy itself is TLS and
		// is verified like any other (server name = proxy host).
		tr.Proxy = http.ProxyURL(&url.URL{Scheme: string(p.Protocol), Host: p.Address()})
		tr.DialContext = dialer.DialContext
	case models.ProtoSOCKS5:
		d, err := proxy.SOCKS5("tcp", p.Address(), nil, dialer)
		if err != nil {
			return nil, fmt.Errorf("creating SOCKS5 dialer: %w", err)
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS5 dialer does not support contexts")
		}
		tr.DialContext = cd.DialContext
	case models.ProtoSOCKS4:
		addr := p.Address()
		tr.DialContext = func(ctx context.Context, _, target string) (net.Conn, error) {
			return socks4.DialContext(ctx, dialer, addr, target)
		}
	default:
		return nil, fmt.Errorf("unsupported protocol %q", p.Protocol)
	}
	return tr, nil
}

// classify maps a transport error to a Reason.
func classify(ctx context.Context, err error) Reason {
	var (
		certErr    *tls.CertificateVerificationError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
		recordErr  tls.RecordHeaderError
		netErr     net.Error
	)
	switch {
	case errors.Is(err, netpolicy.ErrDisallowed):
		return ReasonDisallowedAddress
	case errors.As(err, &certErr), errors.As(err, &unknownCA), errors.As(err, &hostErr),
		errors.As(err, &invalidErr), errors.As(err, &recordErr):
		return ReasonTLS
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.As(err, &netErr) && netErr.Timeout():
		return ReasonTimeout
	case strings.Contains(err.Error(), "tls:"):
		return ReasonTLS
	}
	return ReasonConnect
}

// ParseOrigins extracts the client addresses an httpbin-style probe reports.
// It accepts {"origin": "a, b"} and {"ip": "a"}. Every listed address must be
// a valid IP; they are returned normalized and without duplicates.
func ParseOrigins(body []byte) ([]string, error) {
	var doc struct {
		Origin string `json:"origin"`
		IP     string `json:"ip"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("probe response is not JSON: %w", err)
	}
	raw := doc.Origin
	if raw == "" {
		raw = doc.IP
	}
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("probe response has no origin address")
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("probe origin %q is not an IP address", strings.TrimSpace(part))
		}
		s := addr.Unmap().String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// Baseline holds the client's own public addresses as the probe sees them
// without a proxy. A proxy that lets the probe see one of them leaks.
type Baseline struct {
	mu      sync.RWMutex
	ips     map[string]bool
	updated time.Time
	lastErr string
}

// Set replaces the baseline addresses.
func (b *Baseline) Set(ips []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ips = make(map[string]bool, len(ips))
	for _, ip := range ips {
		if addr, err := netip.ParseAddr(ip); err == nil {
			b.ips[addr.Unmap().String()] = true
		}
	}
	b.updated = time.Now()
	b.lastErr = ""
}

func (b *Baseline) setErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastErr = err.Error()
}

// Known reports whether the baseline has been determined.
func (b *Baseline) Known() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.ips) > 0
}

// Leaks reports whether the baseline is known and whether any origin is one
// of the client's own addresses.
func (b *Baseline) Leaks(origins []string) (known, leak bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.ips) == 0 {
		return false, false
	}
	for _, o := range origins {
		if b.ips[o] {
			return true, true
		}
	}
	return true, false
}

// DetectBaseline asks the probe directly (no proxy, verified TLS, no
// redirects) for the client's own addresses and stores them.
func (c *Checker) DetectBaseline(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     c.tlsConfig.Clone(),
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: c.timeout,
			Proxy:               nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.probeURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		c.baseline.setErr(err)
		return fmt.Errorf("direct probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("direct probe returned status %d", resp.StatusCode)
		c.baseline.setErr(err)
		return err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody+1))
	if err != nil {
		c.baseline.setErr(err)
		return err
	}
	origins, err := ParseOrigins(body)
	if err != nil {
		c.baseline.setErr(err)
		return err
	}
	c.baseline.Set(origins)
	return nil
}

// RunBaseline determines the baseline now and keeps it fresh: it retries
// failures with backoff (5 s doubling to 5 min) and refreshes a known
// baseline every refresh. A failed refresh keeps the previous addresses.
func (c *Checker) RunBaseline(ctx context.Context, refresh time.Duration) {
	backoff := 5 * time.Second
	for {
		wait := refresh
		if err := c.DetectBaseline(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			if c.baseline.Known() {
				slog.Warn("routing baseline refresh failed; keeping previous addresses", "error", err)
			} else {
				slog.Warn("routing baseline unknown; proxies stay unverified until it is detected", "error", err, "retry_in", backoff.String())
				wait = backoff
				backoff = min(backoff*2, 5*time.Minute)
			}
		} else {
			backoff = 5 * time.Second
			slog.Info("routing baseline detected")
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
