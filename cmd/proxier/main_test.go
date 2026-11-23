package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tatlilimon/proxier/internal/fakeproxy"
	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/storage"
	"github.com/tatlilimon/proxier/internal/validator"
)

type flakyStore struct {
	fail  atomic.Bool
	calls atomic.Int64
	saved map[string]*models.Proxy
}

func (f *flakyStore) Apply(up []*models.Proxy, del []string) error {
	f.calls.Add(1)
	if f.fail.Load() {
		return errors.New("simulated disk failure")
	}
	if f.saved == nil {
		f.saved = map[string]*models.Proxy{}
	}
	for _, p := range up {
		f.saved[p.ID] = p
	}
	for _, id := range del {
		delete(f.saved, id)
	}
	return nil
}
func (f *flakyStore) LoadAll() ([]*models.Proxy, error) { return nil, nil }
func (f *flakyStore) Close() error                      { return nil }

// Audit finding 5: a failed write is retried by the next flush.
func TestPersisterRetriesFailedWrites(t *testing.T) {
	p := pool.NewPool()
	p.Add(&models.Proxy{ID: "test", State: models.StateAlive})
	s := &flakyStore{}
	s.fail.Store(true)
	per := &persister{store: s, pool: p}

	per.flush()
	per.flush()
	if s.calls.Load() != 2 {
		t.Fatalf("failed write not retried: Apply calls = %d, want 2", s.calls.Load())
	}
	if st := per.Stats(); st.Failures != 2 || st.Pending != 1 || st.LastError == "" {
		t.Fatalf("stats after failures = %+v", st)
	}

	s.fail.Store(false)
	if err := per.flush(); err != nil {
		t.Fatal(err)
	}
	if st := per.Stats(); st.Pending != 0 || s.saved["test"] == nil || st.LastError != "" {
		t.Fatalf("after recovery: stats %+v saved %v", st, s.saved)
	}
}

func baseConfig(t *testing.T, probe *fakeproxy.Probe, sources []models.SourceConfig) *models.Config {
	cfg := models.DefaultConfig()
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = 0
	cfg.Server.ChannelBufferSize = 100
	cfg.Scanner.Mode = "interval"
	cfg.Scanner.IntervalSec = 3600
	cfg.Scanner.Sources = sources
	cfg.Validator.Workers = 4
	cfg.Validator.TimeoutMs = 1500
	cfg.Validator.ProbeURL = probe.URL + "/ip"
	cfg.Validator.KeepaliveIntervalSec = 1
	cfg.Validator.MaxConsecutiveFails = 2
	cfg.Validator.AllowPrivateProxies = true
	cfg.Storage.Path = filepath.Join(t.TempDir(), "proxies.db")
	return &cfg
}

// Audit finding 14: a listener failure stops the process with an error.
func TestRunFailsWhenThePortIsTaken(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	probe := fakeproxy.NewProbe(t, false)
	cfg := baseConfig(t, probe, nil)
	cfg.Server.Port = busy.Addr().(*net.TCPAddr).Port

	done := make(chan error, 1)
	go func() { done <- run(context.Background(), cfg, runOptions{}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run returned nil with the port taken")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run kept running without its API")
	}
}

type app struct {
	addr string
	stop context.CancelFunc
	done chan error
}

func startApp(t *testing.T, cfg *models.Config, probe *fakeproxy.Probe) *app {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	a := &app{stop: cancel, done: make(chan error, 1)}
	go func() {
		a.done <- run(ctx, cfg, runOptions{
			validatorOpts: []validator.Option{validator.WithRootCAs(probe.RootCAs()), validator.WithScheduleInterval(20 * time.Millisecond)},
			persistEvery:  100 * time.Millisecond,
			maintainEvery: 200 * time.Millisecond,
			ready:         ready,
		})
	}()
	select {
	case a.addr = <-ready:
	case err := <-a.done:
		t.Fatalf("run failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("API never became ready")
	}
	return a
}

func (a *app) shutdown(t *testing.T) {
	t.Helper()
	a.stop()
	select {
	case err := <-a.done:
		if err != nil {
			t.Fatalf("run returned %v on shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown hung")
	}
}

func (a *app) get(t *testing.T, path string, out any) {
	t.Helper()
	resp, err := http.Get("http://" + a.addr + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func (a *app) served(t *testing.T) []string {
	var resp models.ProxiesResponse
	a.get(t, "/proxies?limit=100", &resp)
	var out []string
	for _, p := range resp.Proxies {
		out = append(out, p.Proxy)
	}
	sort.Strings(out)
	return out
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestEndToEnd runs the whole service against local fixtures: list sources,
// working HTTP/SOCKS4/SOCKS5 proxies (HTTPS probe through each), and proxies
// that do not route, intercept TLS or stall. It checks scanning, validation,
// the API, persistence across a restart and demotion of a proxy that stops.
func TestEndToEnd(t *testing.T) {
	probe := fakeproxy.NewProbe(t, true)
	good := map[string]*fakeproxy.Proxy{
		"http":   fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Egress: "127.0.0.2"}),
		"socks5": fakeproxy.NewSOCKS5(t, "127.0.0.3"),
		"socks4": fakeproxy.NewSOCKS4(t, "127.0.0.4"),
	}
	nonRouting := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{}) // egress = client address
	mitm := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{MITM: true})
	stall := fakeproxy.NewStall(t)

	lists := fakeproxy.NewListServer(t)
	lists.Set("/http.txt", fmt.Sprintf("%s\n%s\n%s\n", good["http"].Addr(), nonRouting.Addr(), mitm.Addr()))
	lists.Set("/mixed.txt", fmt.Sprintf("socks5://%s\nsocks4://%s\nsocks5://%s\n", good["socks5"].Addr(), good["socks4"].Addr(), stall.Addr()))
	cfg := baseConfig(t, probe, []models.SourceConfig{
		{URL: lists.URL + "/http.txt", Format: models.FormatTXT, Protocol: models.ProtoHTTP},
		{URL: lists.URL + "/mixed.txt", Format: models.FormatTXT, Protocol: models.ProtoMixed},
	})
	want := []string{
		"http://" + good["http"].Addr(),
		"socks4://" + good["socks4"].Addr(),
		"socks5://" + good["socks5"].Addr(),
	}
	sort.Strings(want)

	a := startApp(t, cfg, probe)
	var stats models.StatsResponse
	waitFor(t, "3 alive and 3 dead proxies", 20*time.Second, func() bool {
		a.get(t, "/stats", &stats)
		return stats.Pool.Alive == 3 && stats.Pool.Dead == 3
	})
	if got := a.served(t); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("served %v, want exactly %v", got, want)
	}
	if stats.Pool.Total != 6 || stats.Pool.Validating+stats.Pool.Discovered != 0 {
		t.Errorf("pool stats = %+v", stats.Pool)
	}
	if stats.Validator.FailureReasons["leaks_client_ip"] == 0 || stats.Validator.FailureReasons["tls_error"] == 0 || stats.Validator.FailureReasons["timeout"] == 0 {
		t.Errorf("failure reasons = %v, want leak, TLS and timeout failures", stats.Validator.FailureReasons)
	}
	if !stats.Validator.RoutingBaselineKnown || stats.Scanner.SourcesOK != 2 {
		t.Errorf("validator %+v scanner %+v", stats.Validator, stats.Scanner)
	}

	// Freshness: with a 1 s keepalive every served proxy was checked recently.
	time.Sleep(2500 * time.Millisecond)
	var list models.ProxiesResponse
	a.get(t, "/proxies?limit=100", &list)
	for _, p := range list.Proxies {
		if age := time.Since(p.LastChecked); age > 2500*time.Millisecond {
			t.Errorf("%s last checked %s ago, want within ~2 keepalive intervals", p.Proxy, age)
		}
	}
	for i := 0; i < 10; i++ {
		var one models.ProxyResponse
		a.get(t, "/proxy", &one)
		if i := sort.SearchStrings(want, one.Proxy); i == len(want) || want[i] != one.Proxy {
			t.Fatalf("/proxy served %q", one.Proxy)
		}
	}
	a.shutdown(t)

	// Restart: the stored records come back and the same three are served.
	st, err := storage.New("sqlite", cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := st.LoadAll()
	st.Close()
	if len(stored) != 6 {
		t.Fatalf("stored %d records, want 6", len(stored))
	}

	a = startApp(t, cfg, probe)
	waitFor(t, "the same proxies after restart", 10*time.Second, func() bool {
		return fmt.Sprint(a.served(t)) == fmt.Sprint(want)
	})

	// A proxy that stops working leaves rotation at its next check.
	good["socks5"].Close()
	waitFor(t, "the stopped proxy to leave rotation", 10*time.Second, func() bool {
		for _, p := range a.served(t) {
			if p == "socks5://"+good["socks5"].Addr() {
				return false
			}
		}
		return true
	})
	a.get(t, "/stats", &stats)
	if stats.Pool.Alive != 2 {
		t.Errorf("alive = %d after the SOCKS5 proxy stopped, want 2", stats.Pool.Alive)
	}
	a.shutdown(t)
}
