package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
)

// seenTTL is the duration a seen proxy address remains in the deduplication
// map before it is eligible for re-entry into the validation pipeline.
const seenTTL = 30 * time.Minute

// Scanner fetches proxy lists from configured sources and forwards discovered
// proxies to a downstream consumer via a channel.
type Scanner struct {
	sources    []models.SourceConfig
	httpClient *http.Client
	interval   time.Duration

	mu              sync.Mutex
	lastRun         time.Time
	nextRun         time.Time
	lastFetchCount  int
	lastDurationMs  int64
	totalDiscovered int64
}

// NewScanner creates a new Scanner with the given proxy sources and scan
// interval.
func NewScanner(sources []models.SourceConfig, interval time.Duration) *Scanner {
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
			log.Printf("scanner: skipping source %s: %v", src.URL, err)
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
		}
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
		log.Printf("scanner: bad JSON from %s: %v", src.URL, err)
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
// present in the recent-seen window. Entries older than seenTTL are re-allowed
// and their timestamp is refreshed. Fresh entries are skipped.
func (s *Scanner) deduplicate(proxies []*models.Proxy, seen map[string]time.Time) []*models.Proxy {
	out := make([]*models.Proxy, 0, len(proxies))
	now := time.Now()
	for _, p := range proxies {
		key := p.Address()
		if lastSeen, ok := seen[key]; ok {
			if now.Sub(lastSeen) < seenTTL {
				continue
			}
			log.Printf("scanner: re-allowing stale proxy %s (last seen %v ago)", key, now.Sub(lastSeen).Truncate(time.Second))
		}
		seen[key] = now
		out = append(out, p)
	}
	return out
}

// cleanupSeen removes entries from the seen map that are older than seenTTL,
// preventing unbounded memory growth.
func (s *Scanner) cleanupSeen(seen map[string]time.Time) {
	cutoff := time.Now().Add(-seenTTL)
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
	}
}
