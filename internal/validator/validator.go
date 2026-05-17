package validator

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
	"golang.org/x/net/proxy"
)

// Pool is the subset of pool.Pool that the validator depends on.
type Pool interface {
	Add(p *models.Proxy)
	Get(id string) (*models.Proxy, bool)
	All() []*models.Proxy
}

// Validator consumes proxy candidates, tests them against a probe URL, and
// maintains health scores in the shared proxy pool.
type Validator struct {
	workers           int
	timeout           time.Duration
	probeURL          string
	maxFails          int
	keepaliveInterval time.Duration
	pool              Pool
	httpClient        *http.Client

	checked      atomic.Int64
	totalLatency atomic.Int64
	successCount atomic.Int64
	failureCount atomic.Int64
}

// NewValidator creates a Validator with the given configuration and pool.
func NewValidator(cfg models.ValidatorConfig, pool Pool) *Validator {
	return &Validator{
		workers:           cfg.Workers,
		timeout:           time.Duration(cfg.TimeoutMs) * time.Millisecond,
		probeURL:          cfg.ProbeURL,
		maxFails:          cfg.MaxConsecutiveFails,
		keepaliveInterval: time.Duration(cfg.KeepaliveIntervalSec) * time.Second,
		pool:              pool,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Run starts the validator worker pool. It reads proxies from the input
// channel, validates each one, and keeps the shared pool up to date.
// Run returns when the input channel is closed and all workers have finished.
func (v *Validator) Run(ctx context.Context, input <-chan *models.Proxy) error {
	var wg sync.WaitGroup

	for i := 0; i < v.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case p, ok := <-input:
					if !ok {
						return
					}
					v.validateOne(ctx, p)
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

// StartKeepalive periodically re-checks every ALIVE proxy in the pool.
// This goroutine runs until ctx is cancelled.
func (v *Validator) StartKeepalive(ctx context.Context) {
	ticker := time.NewTicker(v.keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, p := range v.pool.All() {
				if p.State != models.StateAlive {
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					v.validateOne(ctx, p)
				}
			}

			// Retry recently-dead proxies: up to 50 per cycle, dead within the last hour.
			deadCount := 0
			for _, p := range v.pool.All() {
				if deadCount >= 50 {
					break
				}
				if p.State != models.StateDead {
					continue
				}
				if time.Since(p.LastChecked) > time.Hour {
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("keepalive: retrying recently-dead proxy %s", p.Address())
					v.validateOne(ctx, p)
					deadCount++
				}
			}
		}
	}
}

// validateOne tests a single proxy, updates its state and health score, and
// writes the result back to the pool.
func (v *Validator) validateOne(ctx context.Context, p *models.Proxy) {
	p.State = models.StateValidating

	transport, err := v.createTransport(p)
	if err != nil {
		log.Printf("validator: transport for %s: %v", p.Address(), err)
		v.handleFailure(p)
		return
	}

	// Per-proxy context timeout so a single slow proxy never blocks the worker.
	reqCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, v.probeURL, nil)
	if err != nil {
		log.Printf("validator: request for %s: %v", p.Address(), err)
		v.handleFailure(p)
		return
	}

	client := &http.Client{
		Transport:     transport,
		Timeout:       v.timeout,
		CheckRedirect: v.httpClient.CheckRedirect,
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		log.Printf("validator: %s unreachable (%v)", p.Address(), err)
		v.handleFailure(p)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("validator: %s returned HTTP %d", p.Address(), resp.StatusCode)
		v.handleFailure(p)
		return
	}

	p.LatencyMs = int(latency.Milliseconds())
	p.ConsecutiveOK++
	p.ConsecutiveFail = 0
	p.State = models.StateAlive
	p.HealthScore = v.calcHealthScore(p)
	p.LastChecked = time.Now()

	v.checked.Add(1)
	v.totalLatency.Add(latency.Milliseconds())
	v.successCount.Add(1)

	v.pool.Add(p)
}

// handleFailure increments the fail counter and transitions to DEAD when the
// threshold is reached.
func (v *Validator) handleFailure(p *models.Proxy) {
	p.ConsecutiveFail++
	p.LastChecked = time.Now()
	v.checked.Add(1)
	v.failureCount.Add(1)

	if p.ConsecutiveFail >= v.maxFails {
		p.State = models.StateDead
		p.ConsecutiveOK = 0
		p.HealthScore = 0
		log.Printf("validator: %s marked DEAD (%d consecutive failures)", p.Address(), p.ConsecutiveFail)
	}

	v.pool.Add(p)
}

// createTransport builds an http.Transport that routes through the proxy.
//
// HTTP/HTTPS proxies use http.ProxyURL. SOCKS5 uses golang.org/x/net/proxy.
// SOCKS4 uses a custom dialer that speaks the SOCKS4/SOCKS4a protocol directly.
func (v *Validator) createTransport(p *models.Proxy) (*http.Transport, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	switch p.Protocol {
	case models.ProtoHTTP, models.ProtoHTTPS:
		proxyURL, err := url.Parse(p.URL())
		if err != nil {
			return nil, fmt.Errorf("parsing proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)

	case models.ProtoSOCKS5:
		addr := p.Address()
		dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("creating SOCKS5 dialer: %w", err)
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
		transport.Proxy = nil

	case models.ProtoSOCKS4:
		probeURL, err := url.Parse(v.probeURL)
		if err != nil {
			return nil, fmt.Errorf("parsing probe URL: %w", err)
		}
		probeHost := probeURL.Hostname()
		probePort := probeURL.Port()
		if probePort == "" {
			if probeURL.Scheme == "https" {
				probePort = "443"
			} else {
				probePort = "80"
			}
		}
		portNum, err := strconv.Atoi(probePort)
		if err != nil {
			return nil, fmt.Errorf("invalid probe port %q: %w", probePort, err)
		}

		proxyAddr := p.Address()

		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: v.timeout}
			conn, err := d.DialContext(ctx, "tcp", proxyAddr)
			if err != nil {
				return nil, fmt.Errorf("SOCKS4 connect to %s: %w", proxyAddr, err)
			}

			// Build SOCKS4/SOCKS4a CONNECT request.
			// Format: [VN=4, CD=1, DSTPORT(2 BE), DSTIP(4), USERID\0, (SOCKS4a: HOSTNAME\0)]
			var req []byte
			dstIP := net.ParseIP(probeHost)
			if dstIP != nil && dstIP.To4() != nil {
				// Standard SOCKS4: destination is an IPv4 address.
				req = make([]byte, 0, 9)
				req = append(req, 4, 1) // VN=4, CD=1 (CONNECT)
				req = append(req, byte(portNum>>8), byte(portNum&0xFF))
				req = append(req, dstIP.To4()...)
				req = append(req, 0) // empty user ID
			} else {
				// SOCKS4a: destination is a hostname; encode as 0.0.0.x.
				req = make([]byte, 0, 9+len(probeHost)+1)
				req = append(req, 4, 1) // VN=4, CD=1 (CONNECT)
				req = append(req, byte(portNum>>8), byte(portNum&0xFF))
				req = append(req, 0, 0, 0, 1) // 0.0.0.x (non-zero last byte signals SOCKS4a)
				req = append(req, 0) // empty user ID
				req = append(req, []byte(probeHost)...)
				req = append(req, 0) // null terminator for hostname
			}

			// Set write/read deadline for the handshake.
			if err := conn.SetDeadline(time.Now().Add(v.timeout)); err != nil {
				conn.Close()
				return nil, err
			}

			if _, err := conn.Write(req); err != nil {
				conn.Close()
				return nil, fmt.Errorf("SOCKS4 write request: %w", err)
			}

			// Read the 8-byte SOCKS4 response: [VN, CD, DSTPORT(2), DSTIP(4)]
			resp := make([]byte, 8)
			if _, err := io.ReadFull(conn, resp); err != nil {
				conn.Close()
				return nil, fmt.Errorf("SOCKS4 read response: %w", err)
			}

			// Clear the deadline after handshake so the HTTP exchange can proceed.
			if err := conn.SetDeadline(time.Time{}); err != nil {
				conn.Close()
				return nil, err
			}

			// CD (reply code): 90 = granted, 91 = rejected, 92 = identd, 93 = identd mismatch
			if resp[1] != 90 {
				conn.Close()
				return nil, fmt.Errorf("SOCKS4 request rejected: CD=%d", resp[1])
			}

			return conn, nil
		}
		transport.Proxy = nil

	default:
		return nil, fmt.Errorf("unsupported protocol %q", p.Protocol)
	}

	return transport, nil
}

// calcHealthScore computes a health score between 0 and 1.
//
//	score = latencyScore * 0.4 + successRateScore * 0.6
//
// latencyScore: 1.0 when ≤ 100 ms, linear ramp-down to 0 at ≥ 5000 ms.
// successRateScore: min(consecutiveOK / 10.0, 1.0)
func (v *Validator) calcHealthScore(p *models.Proxy) float64 {
	var latencyScore float64
	switch {
	case p.LatencyMs <= 100:
		latencyScore = 1.0
	case p.LatencyMs >= 5000:
		latencyScore = 0.0
	default:
		latencyScore = 1.0 - float64(p.LatencyMs-100)/4900.0
	}

	successScore := float64(p.ConsecutiveOK) / 10.0
	if successScore > 1.0 {
		successScore = 1.0
	}

	return latencyScore*0.4 + successScore*0.6
}

// Stats returns validator-level statistics. Both counters are updated with
// atomic operations so that this method is safe to call concurrently.
func (v *Validator) Stats() (checkedLastHour int64, avgLatencyMs float64) {
	checked := v.checked.Load()
	totalLat := v.totalLatency.Load()
	if checked == 0 {
		return 0, 0
	}
	return checked, float64(totalLat) / float64(checked)
}

// DetailedStats returns comprehensive validator statistics.
func (v *Validator) DetailedStats() models.ValidatorStats {
	checked := v.checked.Load()
	success := v.successCount.Load()
	failure := v.failureCount.Load()

	var avgLat, rate float64
	if checked > 0 {
		avgLat = float64(v.totalLatency.Load()) / float64(checked)
		rate = float64(success) / float64(checked) * 100
	}

	return models.ValidatorStats{
		Workers:      v.workers,
		TotalChecks:  checked,
		SuccessCount: success,
		FailureCount: failure,
		SuccessRate:  rate,
		AvgLatencyMs: avgLat,
	}
}
