package validator

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
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

// Run starts the validator worker pool. It reads batches of proxies from input,
// validates each one, and keeps the shared pool up to date. Run returns when
// the input channel is closed and all workers have finished.
func (v *Validator) Run(ctx context.Context, input <-chan []*models.Proxy) error {
	var wg sync.WaitGroup

	for i := 0; i < v.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case batch, ok := <-input:
					if !ok {
						return
					}
					for _, p := range batch {
						select {
						case <-ctx.Done():
							return
						default:
							v.validateOne(ctx, p)
						}
					}
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
// SOCKS4 is not supported for validation.
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
		return nil, fmt.Errorf("SOCKS4 validation is not supported")

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
