package validator

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/socks4"
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
	sharedTransport   *http.Transport

	checked      atomic.Int64
	totalLatency atomic.Int64
	successCount atomic.Int64
	failureCount atomic.Int64

	selfIP string
}

// NewValidator creates a Validator with the given configuration and pool.
func NewValidator(cfg models.ValidatorConfig, pool Pool) *Validator {
	v := &Validator{
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

	v.sharedTransport = &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	v.detectSelfIP()

	return v
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

			// Retry stuck VALIDATING proxies: up to 100 per cycle, cooldown 60s.
			validatingCount := 0
			for _, p := range v.pool.All() {
				if validatingCount >= 100 {
					break
				}
				if p.State != models.StateValidating {
					continue
				}
				// Avoid re-validating proxies that were just checked.
				if time.Since(p.LastChecked) < 60*time.Second {
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					slog.Info("keepalive retrying stuck validating proxy", "address", p.Address(), "fails", p.ConsecutiveFail)
					v.validateOne(ctx, p)
					validatingCount++
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
					slog.Info("keepalive retrying recently-dead proxy", "address", p.Address())
					v.validateOne(ctx, p)
					deadCount++
				}
			}
		}
	}
}

// StartKeepaliveWorkers parallelizes keepalive re-validation with dedicated
// workers and optional main-channel push. When count <= 0 and useMainChannel
// is false, it falls back to the existing sequential StartKeepalive.
func (v *Validator) StartKeepaliveWorkers(ctx context.Context, count int, useMainChannel bool, mainCh chan<- *models.Proxy) {
	if count <= 0 && !useMainChannel {
		v.StartKeepalive(ctx)
		return
	}

	keepaliveCh := make(chan *models.Proxy, 5000)

	if count > 0 {
		for i := 0; i < count; i++ {
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case p, ok := <-keepaliveCh:
						if !ok {
							return
						}
						v.validateOne(ctx, p)
					}
				}
			}()
		}
	}

	go func() {
		ticker := time.NewTicker(v.keepaliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				aliveProxies := v.collectAliveProxies()
				slog.Info("keepalive cycle start", "alive_count", len(aliveProxies), "workers", count, "use_main_channel", useMainChannel)

				for _, p := range aliveProxies {
					select {
					case <-ctx.Done():
						return
					default:
					}

					if count > 0 {
						keepaliveCh <- p
					}

					if useMainChannel {
						select {
						case mainCh <- p:
						default:
						}
					}
				}

				// Phase 2: Retry stuck VALIDATING proxies — up to 100 per cycle, cooldown 60s.
				validatingCount := 0
				for _, p := range v.pool.All() {
					if validatingCount >= 100 {
						break
					}
					if p.State != models.StateValidating {
						continue
					}
					if time.Since(p.LastChecked) < 60*time.Second {
						continue
					}
					select {
					case <-ctx.Done():
						return
					default:
						slog.Info("keepalive retrying stuck validating proxy", "address", p.Address(), "fails", p.ConsecutiveFail)
						v.validateOne(ctx, p)
						validatingCount++
					}
				}

				// Phase 3: Retry recently-dead proxies — up to 50 per cycle, dead within the last hour.
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
						slog.Info("keepalive retrying recently-dead proxy", "address", p.Address())
						v.validateOne(ctx, p)
						deadCount++
					}
				}
			}
		}
	}()
}

// collectAliveProxies returns a slice of all proxies currently in the ALIVE state.
func (v *Validator) collectAliveProxies() []*models.Proxy {
	all := v.pool.All()
	alive := make([]*models.Proxy, 0, len(all))
	for _, p := range all {
		if p.State == models.StateAlive {
			alive = append(alive, p)
		}
	}
	return alive
}

// validateOne tests a single proxy, updates its state and health score, and
// writes the result back to the pool.
func (v *Validator) validateOne(ctx context.Context, p *models.Proxy) {
	p.State = models.StateValidating

	transport, err := v.createTransport(p)
	if err != nil {
		slog.Warn("validator transport error", "address", p.Address(), "error", err)
		v.handleFailure(p)
		return
	}

	// Per-proxy context timeout so a single slow proxy never blocks the worker.
	reqCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, v.probeURL, nil)
	if err != nil {
		slog.Warn("validator request error", "address", p.Address(), "error", err)
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
		slog.Debug("validator proxy unreachable", "address", p.Address(), "error", err)
		v.handleFailure(p)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.Debug("validator bad status", "address", p.Address(), "status", resp.StatusCode)
		v.handleFailure(p)
		return
	}

	if v.selfIP != "" {
		originIP := parseOriginIP(resp)
		if originIP == v.selfIP {
			slog.Warn("validator proxy NOT routing", "address", p.Address(), "origin", originIP)
			v.handleFailure(p)
			return
		}
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
		slog.Warn("validator proxy marked dead", "address", p.Address(), "consecutive_fails", p.ConsecutiveFail)
	}

	v.pool.Add(p)
}

// createTransport builds an http.Transport that routes through the proxy.
//
// HTTP/HTTPS proxies use http.ProxyURL. SOCKS5 uses golang.org/x/net/proxy.
// SOCKS4 uses a custom dialer that speaks the SOCKS4/SOCKS4a protocol directly.
func (v *Validator) createTransport(p *models.Proxy) (*http.Transport, error) {
	transport := v.sharedTransport.Clone()

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
			return socks4.Dial(ctx, probeHost, portNum, proxyAddr, v.timeout)
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

// detectSelfIP fetches our own public IP via the probe URL to detect
// proxies that accept connections but don't actually route traffic.
func (v *Validator) detectSelfIP() {
	client := &http.Client{
		Timeout: v.timeout,
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:  true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	resp, err := client.Get(v.probeURL)
	if err != nil {
		slog.Warn("failed to detect self IP, routing verification disabled", "error", err)
		return
	}
	defer resp.Body.Close()

	ip := parseOriginIP(resp)
	if ip == "" {
		slog.Warn("failed to parse self IP from probe response, routing verification disabled")
		return
	}

	v.selfIP = ip
	slog.Info("self IP detected for routing verification", "ip", ip)
}

type originResponse struct {
	Origin string `json:"origin"`
}

// parseOriginIP extracts the origin IP from an httpbin-style JSON response
// body. Returns "" on any parse error (caller should treat as indeterminate).
func parseOriginIP(resp *http.Response) string {
	var body originResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return ""
	}
	return body.Origin
}
