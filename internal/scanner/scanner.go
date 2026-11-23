// Package scanner fetches proxy lists from the configured sources and hands
// new candidates to the pool.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/netpolicy"
)

// Sink receives candidates. pool.Pool implements it: Merge stores every
// candidate (nothing is dropped) and returns how many were new.
type Sink interface {
	Merge(candidates []models.Proxy) int
}

var colonSpaces = regexp.MustCompile(`[ \t]*:[ \t]*`)

// maxConcurrentFetches bounds parallel source downloads.
const maxConcurrentFetches = 5

// Scanner fetches proxy lists from configured sources.
type Scanner struct {
	sources      []models.SourceConfig
	httpClient   *http.Client
	interval     time.Duration
	dedupTTL     time.Duration
	allowPrivate bool

	mu              sync.Mutex
	lastRun         time.Time
	nextRun         time.Time
	lastFetchCount  int
	lastNewCount    int
	lastDurationMs  int64
	totalDiscovered int64
	status          map[string]*models.SourceStatus

	rejected atomic.Int64
}

// NewScanner creates a Scanner with the given sources, scan interval and
// deduplication TTL. allowPrivate admits candidates on non-public addresses.
func NewScanner(sources []models.SourceConfig, interval, dedupTTL time.Duration, allowPrivate bool) *Scanner {
	s := &Scanner{
		sources: sources,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				MaxConnsPerHost:   4,
			},
		},
		interval:     interval,
		dedupTTL:     dedupTTL,
		allowPrivate: allowPrivate,
		status:       make(map[string]*models.SourceStatus, len(sources)),
	}
	for _, src := range sources {
		s.status[src.URL] = &models.SourceStatus{URL: RedactURL(src.URL), Protocol: src.Protocol}
	}
	return s
}

// sensitiveParams are query parameters whose values are masked wherever a
// source URL is shown (logs, /stats, /metrics): list URLs of paid services
// often carry an API key.
var sensitiveParams = []string{"key", "token", "secret", "password", "passwd", "pass", "auth", "sig", "signature", "credential"}

// RedactURL removes user information and masks the values of query
// parameters that look like credentials, keeping the URL recognisable and
// distinct per source.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "invalid-url"
	}
	u.User = nil
	q := u.Query()
	changed := false
	for name := range q {
		lower := strings.ToLower(name)
		for _, s := range sensitiveParams {
			if strings.Contains(lower, s) {
				q.Set(name, "REDACTED")
				changed = true
				break
			}
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Run fetches all sources immediately and then on every interval tick, until
// ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, sink Sink) {
	seen := make(map[string]time.Time)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		start := time.Now()
		s.mu.Lock()
		s.nextRun = start.Add(s.interval)
		s.mu.Unlock()
		s.cycle(ctx, sink, seen, start)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunContinuous fetches all sources, then waits delaySec seconds after the
// cycle completes, and repeats until ctx is cancelled.
func (s *Scanner) RunContinuous(ctx context.Context, sink Sink, delaySec int) {
	seen := make(map[string]time.Time)
	delay := time.Duration(delaySec) * time.Second

	for {
		start := time.Now()
		s.cycle(ctx, sink, seen, start)

		s.mu.Lock()
		s.nextRun = time.Now().Add(delay)
		s.mu.Unlock()

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// cycle runs one scan: fetch every source in parallel, drop candidates seen
// within the dedup TTL, hand the rest to the sink and only then mark them
// seen, so a candidate is never suppressed without having been stored.
func (s *Scanner) cycle(ctx context.Context, sink Sink, seen map[string]time.Time, start time.Time) {
	if ctx.Err() != nil {
		return
	}
	s.cleanupSeen(seen)
	all := s.fetchAllSources(ctx)
	fresh := s.deduplicate(all, seen)

	batch := make([]models.Proxy, len(fresh))
	for i, p := range fresh {
		batch[i] = *p
	}
	added := 0
	if len(batch) > 0 {
		added = sink.Merge(batch)
	}
	s.markSeen(fresh, seen, time.Now())

	s.mu.Lock()
	s.lastRun = start
	s.lastFetchCount = len(all)
	s.lastNewCount = added
	s.lastDurationMs = time.Since(start).Milliseconds()
	s.totalDiscovered += int64(added)
	s.mu.Unlock()

	slog.Info("scan cycle",
		"fetched", len(all), "fresh", len(fresh), "new", added,
		"duration_ms", time.Since(start).Milliseconds())
}

// fetchAllSources downloads every source with at most maxConcurrentFetches
// in parallel and returns all parsed candidates.
func (s *Scanner) fetchAllSources(ctx context.Context) []*models.Proxy {
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		all       []*models.Proxy
		semaphore = make(chan struct{}, maxConcurrentFetches)
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

			attempt := time.Now()
			proxies, err := s.fetchSource(ctx, src)
			s.recordSource(src, attempt, len(proxies), err)
			if err != nil {
				if ctx.Err() == nil {
					slog.Warn("scanner skipping source", "url", RedactURL(src.URL), "error", err)
				}
				return
			}
			mu.Lock()
			all = append(all, proxies...)
			mu.Unlock()
		}(src)
	}

	wg.Wait()
	return all
}

func (s *Scanner) recordSource(src models.SourceConfig, attempt time.Time, count int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.status[src.URL]
	if !ok {
		st = &models.SourceStatus{URL: RedactURL(src.URL), Protocol: src.Protocol}
		s.status[src.URL] = st
	}
	st.LastAttempt = attempt
	st.LastCount = count
	if err != nil {
		st.OK = false
		st.LastError = err.Error()
		return
	}
	st.OK = true
	st.LastError = ""
	st.LastSuccess = attempt
}

// fetchSource downloads a proxy list and parses it according to its format.
func (s *Scanner) fetchSource(ctx context.Context, src models.SourceConfig) ([]*models.Proxy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "proxier/1.0 (proxy-rotator)")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			ue.URL = RedactURL(ue.URL)
		}
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

// parseTXT reads one proxy per line. A line is "host:port" (IPv6 hosts in
// brackets) or "scheme://host:port"; anything after the first whitespace is
// ignored, as are empty and "#" comment lines. A scheme on the line wins over
// the source protocol. For a "mixed" source an unprefixed line yields one
// candidate per protocol in models.MixedProtocols.
func (s *Scanner) parseTXT(body []byte, src models.SourceConfig) []*models.Proxy {
	var proxies []*models.Proxy
	sc := bufio.NewScanner(bytes.NewReader(body))
	now := time.Now()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "host : port" is accepted; anything after the address is ignored.
		line = colonSpaces.ReplaceAllString(line, ":")
		if fields := strings.Fields(line); len(fields) > 0 {
			line = fields[0]
		}
		protos, host, port, ok := s.parseLine(line, src.Protocol)
		if !ok {
			continue
		}
		for _, proto := range protos {
			c := models.NewCandidate(proto, host, port, src.URL, now)
			proxies = append(proxies, &c)
		}
	}
	return proxies
}

func (s *Scanner) parseLine(line string, sourceProto models.Protocol) ([]models.Protocol, string, int, bool) {
	var (
		host    string
		portStr string
		protos  []models.Protocol
	)
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" || u.Port() == "" || u.User != nil {
			return nil, "", 0, false
		}
		proto, ok := models.ParseScheme(u.Scheme)
		if !ok {
			return nil, "", 0, false
		}
		protos = []models.Protocol{proto}
		host, portStr = u.Hostname(), u.Port()
	} else {
		h, p, err := net.SplitHostPort(line)
		if err != nil {
			return nil, "", 0, false
		}
		host, portStr = h, p
		protos = protocolsFor(sourceProto)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || !s.hostAcceptable(host) {
		return nil, "", 0, false
	}
	return protos, host, port, len(protos) > 0
}

func protocolsFor(p models.Protocol) []models.Protocol {
	if p == models.ProtoMixed {
		return models.MixedProtocols
	}
	if p.Valid() {
		return []models.Protocol{p}
	}
	return nil
}

// hostAcceptable rejects malformed hosts and, unless private destinations are
// allowed, IP literals on non-public addresses.
func (s *Scanner) hostAcceptable(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t,/@") {
		return false
	}
	if ip := net.ParseIP(host); ip == nil && !validHostname(host) {
		return false
	}
	if err := netpolicy.CheckHost(host, s.allowPrivate); err != nil {
		s.rejected.Add(1)
		return false
	}
	return true
}

func validHostname(h string) bool {
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return false
		}
	}
	return !strings.HasPrefix(h, "-") && !strings.HasPrefix(h, ".")
}

// jsonProxy is one entry of a JSON source: an array of objects with "ip" or
// "host", "port", and optionally "protocol".
type jsonProxy struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (s *Scanner) parseJSON(body []byte, src models.SourceConfig) []*models.Proxy {
	var entries []jsonProxy
	if err := json.Unmarshal(body, &entries); err != nil {
		slog.Warn("scanner bad JSON", "url", RedactURL(src.URL), "error", err)
		return nil
	}

	var proxies []*models.Proxy
	now := time.Now()
	for _, e := range entries {
		host := e.Host
		if host == "" {
			host = e.IP
		}
		if e.Port < 1 || e.Port > 65535 || !s.hostAcceptable(host) {
			continue
		}
		protos := protocolsFor(src.Protocol)
		if p, ok := models.ParseScheme(e.Protocol); ok {
			protos = []models.Protocol{p}
		}
		for _, proto := range protos {
			c := models.NewCandidate(proto, host, e.Port, src.URL, now)
			proxies = append(proxies, &c)
		}
	}
	return proxies
}

// dedupKey identifies a candidate for deduplication: protocol, host and port.
func dedupKey(p *models.Proxy) string {
	return p.URL()
}

// deduplicate returns the candidates not seen within the dedup TTL, without
// duplicates inside the batch. It does not record them: markSeen does that
// once they have been handed to the sink.
func (s *Scanner) deduplicate(proxies []*models.Proxy, seen map[string]time.Time) []*models.Proxy {
	out := make([]*models.Proxy, 0, len(proxies))
	now := time.Now()
	batch := make(map[string]bool, len(proxies))
	for _, p := range proxies {
		key := dedupKey(p)
		if batch[key] {
			continue
		}
		if lastSeen, ok := seen[key]; ok && now.Sub(lastSeen) < s.dedupTTL {
			continue
		}
		batch[key] = true
		out = append(out, p)
	}
	return out
}

// markSeen records candidates that were handed to the sink.
func (s *Scanner) markSeen(proxies []*models.Proxy, seen map[string]time.Time, now time.Time) {
	for _, p := range proxies {
		seen[dedupKey(p)] = now
	}
}

// cleanupSeen removes entries older than the dedup TTL.
func (s *Scanner) cleanupSeen(seen map[string]time.Time) {
	cutoff := time.Now().Add(-s.dedupTTL)
	for key, ts := range seen {
		if ts.Before(cutoff) {
			delete(seen, key)
		}
	}
}

// DetailedStats returns scanner statistics, including per-source outcomes.
func (s *Scanner) DetailedStats() models.ScannerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := models.ScannerStats{
		LastRun:         s.lastRun,
		NextRun:         s.nextRun,
		SourcesCount:    len(s.sources),
		LastFetchCount:  s.lastFetchCount,
		LastNewCount:    s.lastNewCount,
		TotalDiscovered: s.totalDiscovered,
		LastDurationMs:  s.lastDurationMs,
		Rejected:        s.rejected.Load(),
	}
	for _, src := range s.sources {
		if st, ok := s.status[src.URL]; ok {
			stats.Sources = append(stats.Sources, *st)
			if st.OK {
				stats.SourcesOK++
			}
		}
	}
	return stats
}
