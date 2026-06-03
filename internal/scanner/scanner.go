package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
)

// Scanner fetches proxy lists from configured sources and forwards discovered
// proxies to a downstream consumer via a channel.
type Scanner struct {
	sources    []models.SourceConfig
	httpClient *http.Client
	interval   time.Duration
	dedupTTL   time.Duration

	mu              sync.Mutex
	lastRun         time.Time
	nextRun         time.Time
	lastFetchCount  int
	lastDurationMs  int64
	totalDiscovered int64

	// dropped counts proxies discarded because the output channel was full.
	dropped atomic.Int64
}

// NewScanner creates a new Scanner with the given proxy sources, scan
// interval, and deduplication TTL.
func NewScanner(sources []models.SourceConfig, interval time.Duration, dedupTTL time.Duration) *Scanner {
	return &Scanner{
		sources: sources,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives:   true,
				IdleConnTimeout:     90 * time.Second,
				MaxConnsPerHost:     4,
				MaxIdleConns:        0,
				MaxIdleConnsPerHost: 0,
			},
		},
		interval: interval,
		dedupTTL: dedupTTL,
	}
}

// Run starts the scanner's main loop. It fetches all sources immediately on
// start and then repeats on each interval tick. Every run deduplicates
// discovered proxies and sends only the new batch to output. The loop exits
// when ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, output chan<- *models.Proxy) {
	seen := make(map[string]time.Time)

	// Initial fetch.
	s.runOnce(ctx, output, seen)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx, output, seen)
		}
	}
}

// runOnce fetches every source, deduplicates the combined result, and sends
// the new proxies downstream. Failures from individual sources are logged and
// skipped.
func (s *Scanner) runOnce(ctx context.Context, output chan<- *models.Proxy, seen map[string]time.Time) {
	s.cleanupSeen(seen)

	start := time.Now()
	now := start

	s.mu.Lock()
	s.lastRun = now
	s.nextRun = now.Add(s.interval)
	s.mu.Unlock()

	var all []*models.Proxy

	for _, src := range s.sources {
		proxies, err := s.fetchSource(ctx, src)
		if err != nil {
			slog.Warn("scanner skipping source", "url", src.URL, "error", err)
			continue
		}
		all = append(all, proxies...)
	}

	newProxies := s.deduplicate(all, seen)

	s.mu.Lock()
	s.lastFetchCount = len(all)
	s.lastDurationMs = time.Since(start).Milliseconds()
	s.totalDiscovered += int64(len(newProxies))
	s.mu.Unlock()

	for _, p := range newProxies {
		select {
		case <-ctx.Done():
			return
		case output <- p:
		default:
			s.dropped.Add(1)
		}
	}
}

// fetchAllSources fetches every source in parallel (max 5 concurrent),
// deduplicates the result against the seen map, and returns only new proxies.
// It does NOT write to the output channel. The caller is responsible for
// forwarding the result.
func (s *Scanner) fetchAllSources(ctx context.Context, seen map[string]time.Time) []*models.Proxy {
	s.cleanupSeen(seen)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		all       []*models.Proxy
		semaphore = make(chan struct{}, 5)
	)

	for _, src := range s.sources {
		wg.Add(1)
		go func(src models.SourceConfig) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			proxies, err := s.fetchSource(ctx, src)
			if err != nil {
				slog.Warn("scanner skipping source", "url", src.URL, "error", err)
				return
			}

			mu.Lock()
			all = append(all, proxies...)
			mu.Unlock()
		}(src)
	}

	wg.Wait()
	return s.deduplicate(all, seen)
}

// pushToChannel sends proxies to the output channel with non-blocking sends.
// Dropped proxies (when the channel is full) are counted via the shared atomic
// counter and also returned so the caller can report per-cycle statistics.
func (s *Scanner) pushToChannel(ctx context.Context, output chan<- *models.Proxy, proxies []*models.Proxy) int {
	dropped := 0
	for _, p := range proxies {
		select {
		case <-ctx.Done():
			return dropped
		case output <- p:
		default:
			s.dropped.Add(1)
			dropped++
		}
	}
	return dropped
}

// RunContinuous runs a tight fetch→push→sleep loop. Every cycle fetches all
// sources, deduplicates against a rolling seen window, pushes new proxies to
// the output channel, and then sleeps for delaySec seconds. The delay applies
// after the cycle completes (including fetch time). The loop exits when ctx is
// cancelled.
func (s *Scanner) RunContinuous(ctx context.Context, output chan<- *models.Proxy, delaySec int) {
	seen := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		start := time.Now()

		newProxies := s.fetchAllSources(ctx, seen)

		droppedThisCycle := s.pushToChannel(ctx, output, newProxies)

		s.mu.Lock()
		s.lastRun = start
		s.nextRun = start.Add(time.Duration(delaySec) * time.Second)
		s.lastFetchCount = len(newProxies)
		s.lastDurationMs = time.Since(start).Milliseconds()
		s.totalDiscovered += int64(len(newProxies))
		s.mu.Unlock()

		slog.Info("continuous scan cycle",
			"fetched", len(newProxies),
			"dropped", droppedThisCycle,
			"next_delay_sec", delaySec,
		)

		time.Sleep(time.Duration(delaySec) * time.Second)
	}
}

// fetchSource downloads a proxy list from the given source and dispatches to
// the correct parser based on the source's Format field.
func (s *Scanner) fetchSource(ctx context.Context, src models.SourceConfig) ([]*models.Proxy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "proxier/1.0 (proxy-rotator)")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	switch src.Format {
	case models.FormatJSON:
		return s.parseJSON(body, src), nil
	default:
		return s.parseTXT(body, src), nil
	}
}

// parseTXT splits the body by newlines and extracts "host:port" pairs.
// Empty lines, comment lines (starting with #), and lines that do not contain
// a single colon are silently skipped.
func (s *Scanner) parseTXT(body []byte, src models.SourceConfig) []*models.Proxy {
	var proxies []*models.Proxy
	sc := bufio.NewScanner(bytes.NewReader(body))

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Must contain exactly one colon separating host and port.
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		host := strings.TrimSpace(parts[0])
		portStr := strings.TrimSpace(parts[1])
		if host == "" || portStr == "" {
			continue
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue
		}

		// Filter out clearly invalid host strings (e.g. lines containing
		// spaces or descriptive text).
		if strings.ContainsAny(host, " \t,/") {
			continue
		}

		// Accept both raw IPs and hostnames.
		if ip := net.ParseIP(host); ip == nil {
			// Not an IP — treat as hostname; do a light sanity check.
			if len(host) > 253 {
				continue
			}
		}

		proxy := &models.Proxy{
			ID:        models.ProxyID(host, port),
			Host:      host,
			Port:      port,
			Protocol:  src.Protocol,
			State:     models.StateDiscovered,
			Source:    src.URL,
			FirstSeen: time.Now().UTC(),
		}
		proxies = append(proxies, proxy)
	}

	return proxies
}

// jsonProxy is a helper struct for unmarshalling JSON arrays whose elements
// carry ip/host and port fields.
type jsonProxy struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// parseJSON expects a JSON array of objects with "ip" (or "host") and "port"
// numeric fields. Every other shape is silently ignored.
func (s *Scanner) parseJSON(body []byte, src models.SourceConfig) []*models.Proxy {
	var entries []jsonProxy
	if err := json.Unmarshal(body, &entries); err != nil {
		slog.Warn("scanner bad JSON", "url", src.URL, "error", err)
		return nil
	}

	var proxies []*models.Proxy

	for _, e := range entries {
		host := e.Host
		if host == "" {
			host = e.IP
		}
		if host == "" || e.Port < 1 || e.Port > 65535 {
			continue
		}

		proxy := &models.Proxy{
			ID:        models.ProxyID(host, e.Port),
			Host:      host,
			Port:      e.Port,
			Protocol:  src.Protocol,
			State:     models.StateDiscovered,
			Source:    src.URL,
			FirstSeen: time.Now().UTC(),
		}
		proxies = append(proxies, proxy)
	}

	return proxies
}

// deduplicate filters proxies, keeping only those whose host:port key is not
// present in the recent-seen window. Entries older than the dedup TTL are
// re-allowed and their timestamp is refreshed. Fresh entries are skipped.
func (s *Scanner) deduplicate(proxies []*models.Proxy, seen map[string]time.Time) []*models.Proxy {
	out := make([]*models.Proxy, 0, len(proxies))
	now := time.Now()
	for _, p := range proxies {
		key := p.Address()
		if lastSeen, ok := seen[key]; ok {
			if now.Sub(lastSeen) < s.dedupTTL {
				continue
			}
			slog.Info("scanner re-allowing stale proxy", "address", key, "age", now.Sub(lastSeen).Truncate(time.Second).String())
		}
		seen[key] = now
		out = append(out, p)
	}
	return out
}

// cleanupSeen removes entries from the seen map that are older than the dedup
// TTL, preventing unbounded memory growth.
func (s *Scanner) cleanupSeen(seen map[string]time.Time) {
	cutoff := time.Now().Add(-s.dedupTTL)
	for key, ts := range seen {
		if ts.Before(cutoff) {
			delete(seen, key)
		}
	}
}

// Stats returns the current scanner statistics.
func (s *Scanner) Stats() (lastRun time.Time, nextRun time.Time, sourceCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRun, s.nextRun, len(s.sources)
}

// DetailedStats returns comprehensive scanner statistics.
func (s *Scanner) DetailedStats() models.ScannerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return models.ScannerStats{
		LastRun:         s.lastRun,
		NextRun:         s.nextRun,
		SourcesCount:    len(s.sources),
		LastFetchCount:  s.lastFetchCount,
		TotalDiscovered: s.totalDiscovered,
		LastDurationMs:  s.lastDurationMs,
		Dropped:         s.dropped.Load(),
	}
}
