package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tatlilimon/proxier/internal/fakeproxy"
	"github.com/tatlilimon/proxier/internal/models"
)

type recordingSink struct {
	mu      sync.Mutex
	batches [][]models.Proxy
	known   map[string]bool
}

func (r *recordingSink) Merge(c []models.Proxy) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.known == nil {
		r.known = map[string]bool{}
	}
	r.batches = append(r.batches, c)
	added := 0
	for _, p := range c {
		if !r.known[p.ID] {
			r.known[p.ID] = true
			added++
		}
	}
	return added
}

func (r *recordingSink) all() []models.Proxy {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []models.Proxy
	for _, b := range r.batches {
		out = append(out, b...)
	}
	return out
}

func protocolsOf(ps []*models.Proxy) map[models.Protocol]int {
	out := map[models.Protocol]int{}
	for _, p := range ps {
		out[p.Protocol]++
	}
	return out
}

// Audit finding 10: a mixed source has a defined format.
func TestParseTXTMixedSource(t *testing.T) {
	s := NewScanner(nil, time.Minute, time.Minute, false)
	src := models.SourceConfig{URL: "mixed", Protocol: models.ProtoMixed}
	body := "198.51.100.1:8080\nsocks5://198.51.100.2:1080\nsocks4a://198.51.100.3:1080\nhttps://198.51.100.4:443\nftp://198.51.100.5:21\n"

	got := s.parseTXT([]byte(body), src)
	protos := protocolsOf(got)
	// Unprefixed: http, socks4 and socks5; then one per recognised scheme.
	if len(got) != 6 || protos[models.ProtoHTTP] != 1 || protos[models.ProtoSOCKS4] != 2 ||
		protos[models.ProtoSOCKS5] != 2 || protos[models.ProtoHTTPS] != 1 {
		t.Fatalf("got %d candidates %v", len(got), protos)
	}
	for _, p := range got {
		if !p.Protocol.Valid() || p.ID != models.ProxyID(p.Protocol, p.Host, p.Port) {
			t.Errorf("candidate %s has protocol %q / id %s", p.URL(), p.Protocol, p.ID)
		}
	}
}

func TestParseTXTSchemeOverridesSourceProtocol(t *testing.T) {
	s := NewScanner(nil, time.Minute, time.Minute, false)
	got := s.parseTXT([]byte("socks5://198.51.100.2:1080 # comment\n198.51.100.1 : 8080 US"), models.SourceConfig{Protocol: models.ProtoHTTP})
	if len(got) != 2 || got[0].Protocol != models.ProtoSOCKS5 || got[1].Protocol != models.ProtoHTTP || got[1].Port != 8080 {
		t.Fatalf("got %+v", got)
	}
}

// Audit finding 15: hostile lists cannot point the validator at private
// addresses unless the operator opts in.
func TestParseRefusesPrivateAddressesUnlessAllowed(t *testing.T) {
	body := []byte("127.0.0.1:8080\n10.1.2.3:3128\n169.254.169.254:80\n[::1]:80\n198.51.100.1:8080\n")
	src := models.SourceConfig{Protocol: models.ProtoHTTP}

	strict := NewScanner(nil, time.Minute, time.Minute, false)
	if got := strict.parseTXT(body, src); len(got) != 1 || got[0].Host != "198.51.100.1" {
		t.Fatalf("strict: got %+v, want only the public address", got)
	}
	if strict.DetailedStats().Rejected != 4 {
		t.Errorf("rejected = %d, want 4", strict.DetailedStats().Rejected)
	}
	open := NewScanner(nil, time.Minute, time.Minute, true)
	if got := open.parseTXT(body, src); len(got) != 5 {
		t.Fatalf("opt-in: got %d, want 5", len(got))
	}
}

// Audit finding 10: an HTTP listing must not suppress a SOCKS5 candidate at
// the same address.
func TestDeduplicateKeepsProtocolAlternatives(t *testing.T) {
	s := NewScanner(nil, time.Minute, 30*time.Minute, false)
	a := models.NewCandidate(models.ProtoHTTP, "192.0.2.1", 80, "a", time.Now())
	b := models.NewCandidate(models.ProtoSOCKS5, "192.0.2.1", 80, "b", time.Now())
	if got := s.deduplicate([]*models.Proxy{&a, &b}, map[string]time.Time{}); len(got) != 2 {
		t.Fatalf("kept %d of 2 distinct-protocol candidates", len(got))
	}
}

// Audit finding 10: a candidate is only suppressed after it was stored, and
// the pool never drops candidates.
func TestCycleNeverSuppressesUnstoredCandidates(t *testing.T) {
	lists := fakeproxy.NewListServer(t)
	lists.Set("/http.txt", "198.51.100.1:8080\n198.51.100.2:8080\n")
	src := models.SourceConfig{URL: lists.URL + "/http.txt", Format: models.FormatTXT, Protocol: models.ProtoHTTP}
	s := NewScanner([]models.SourceConfig{src}, time.Minute, 30*time.Minute, false)

	seen := map[string]time.Time{}
	sink := &recordingSink{}
	s.cycle(context.Background(), sink, seen, time.Now())
	if len(sink.all()) != 2 || len(seen) != 2 {
		t.Fatalf("first cycle stored %d and marked %d, want 2 and 2", len(sink.all()), len(seen))
	}
	s.cycle(context.Background(), sink, seen, time.Now())
	if len(sink.all()) != 2 {
		t.Fatalf("second cycle within the TTL re-offered candidates: %d", len(sink.all()))
	}

	stats := s.DetailedStats()
	if stats.TotalDiscovered != 2 || stats.LastFetchCount != 2 || stats.LastNewCount != 0 || stats.SourcesOK != 1 {
		t.Errorf("stats = %+v", stats)
	}
}

// Audit finding 19: interval mode fetches sources in parallel and reports
// per-source outcomes.
func TestFetchAllSourcesIsParallelAndReportsSources(t *testing.T) {
	lists := fakeproxy.NewListServer(t)
	lists.Set("/a.txt", "198.51.100.1:8080\n")
	lists.Set("/b.txt", "198.51.100.2:8080\n")
	srcs := []models.SourceConfig{
		{URL: lists.URL + "/a.txt", Protocol: models.ProtoHTTP},
		{URL: lists.URL + "/b.txt", Protocol: models.ProtoSOCKS5},
		{URL: lists.URL + "/missing.txt", Protocol: models.ProtoHTTP},
	}
	s := NewScanner(srcs, time.Minute, time.Minute, false)
	got := s.fetchAllSources(context.Background())
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2", len(got))
	}
	stats := s.DetailedStats()
	if stats.SourcesCount != 3 || stats.SourcesOK != 2 || len(stats.Sources) != 3 {
		t.Fatalf("stats = %+v", stats)
	}
	if st := stats.Sources[2]; st.OK || st.LastError == "" || !st.LastSuccess.IsZero() {
		t.Errorf("missing source status = %+v", st)
	}
}

func TestRunContinuousSchedulesAfterCompletionAndStops(t *testing.T) {
	lists := fakeproxy.NewListServer(t)
	lists.Set("/a.txt", "198.51.100.1:8080\n")
	s := NewScanner([]models.SourceConfig{{URL: lists.URL + "/a.txt", Protocol: models.ProtoHTTP}}, time.Minute, time.Minute, false)
	sink := &recordingSink{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunContinuous(ctx, sink, 3600); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for s.DetailedStats().NextRun.IsZero() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	st := s.DetailedStats()
	if st.NextRun.Sub(st.LastRun) < time.Hour {
		t.Errorf("next_run %s is not one delay after the cycle (last_run %s)", st.NextRun, st.LastRun)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunContinuous did not stop during its delay")
	}
}

func TestSourceURLsAreRedactedWhereShown(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:pw@lists.example/p.txt?api_key=s3cret&protocol=http": "https://lists.example/p.txt?api_key=REDACTED&protocol=http",
		"https://lists.example/p.txt?protocol=socks5&limit=2000":           "https://lists.example/p.txt?protocol=socks5&limit=2000",
		"https://lists.example/p.txt?token=abc":                            "https://lists.example/p.txt?token=REDACTED",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}

	src := models.SourceConfig{URL: "http://127.0.0.1:1/p.txt?token=s3cret", Protocol: models.ProtoHTTP}
	s := NewScanner([]models.SourceConfig{src}, time.Minute, time.Minute, false)
	s.fetchAllSources(context.Background())
	st := s.DetailedStats().Sources[0]
	if strings.Contains(st.URL, "s3cret") || strings.Contains(st.LastError, "s3cret") || st.LastError == "" {
		t.Fatalf("source status leaks the token: %+v", st)
	}
}
