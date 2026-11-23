package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tatlilimon/proxier/internal/fakeproxy"
	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/scanner"
	"github.com/tatlilimon/proxier/internal/validator"
)

type testAPI struct {
	srv   *Server
	pool  *pool.Pool
	val   *validator.Validator
	probe *fakeproxy.Probe
}

func newAPI(t *testing.T, allowPrivate bool) *testAPI {
	t.Helper()
	probe := fakeproxy.NewProbe(t, false)
	p := pool.NewPool()
	cfg := models.ValidatorConfig{Workers: 1, TimeoutMs: 1500, ProbeURL: probe.URL + "/ip", KeepaliveIntervalSec: 60, MaxConsecutiveFails: 3, AllowPrivateProxies: allowPrivate}
	v, err := validator.NewValidator(cfg, 10, p, validator.WithBaselineRefresh(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Checker().DetectBaseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := scanner.NewScanner(nil, time.Minute, time.Minute, allowPrivate)
	srv := NewServer(models.ServerConfig{Host: "127.0.0.1", Port: 0}, Deps{Pool: p, Validator: v, Scanner: s, AllowPrivate: allowPrivate})
	return &testAPI{srv: srv, pool: p, val: v, probe: probe}
}

func (a *testAPI) do(t *testing.T, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.srv.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	out := map[string]any{}
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// Audit finding 15: malformed input is rejected.
func TestParseProxyStringRejectsInvalidInput(t *testing.T) {
	for _, in := range []string{
		"ftp://198.51.100.1:80", "http://:80", "http://198.51.100.1:0", "http://198.51.100.1:99999",
		"198.51.100.1:-1", "198.51.100.1", "http://user:pass@198.51.100.1:80", "http://198.51.100.1:80/path",
		"mixed://198.51.100.1:80",
	} {
		if _, _, _, err := parseProxyString(in); err == nil {
			t.Errorf("accepted invalid input %q", in)
		}
	}
}

// Audit finding 18: IPv6 proxies are accepted and formatted correctly.
func TestParseProxyStringIPv6(t *testing.T) {
	host, port, proto, err := parseProxyString("socks5h://[2001:DB8::1]:1080")
	if err != nil {
		t.Fatal(err)
	}
	p := models.Proxy{Host: host, Port: port, Protocol: proto}
	if p.Address() != "[2001:db8::1]:1080" || p.URL() != "socks5://[2001:db8::1]:1080" {
		t.Fatalf("Address=%s URL=%s", p.Address(), p.URL())
	}
}

// Audit finding 15: by default /validate refuses loopback proxies and never
// contacts them.
func TestValidateRefusesLoopbackByDefault(t *testing.T) {
	a := newAPI(t, false)
	fx := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Body: "<html>not a proxy</html>"})
	rec, _ := a.do(t, "POST", "/validate", fmt.Sprintf(`{"proxy":"http://%s"}`, fx.Addr()))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body)
	}
	if fx.Handled.Load() != 0 {
		t.Fatal("the loopback endpoint was contacted")
	}
}

// Audit finding 7: /validate uses the same engine as background validation:
// SOCKS4 speaks SOCKS4, redirects and login pages fail, routing is verified.
func TestValidateMatchesBackgroundValidation(t *testing.T) {
	a := newAPI(t, true)
	cases := []struct {
		name  string
		proxy string
		alive bool
		why   string
	}{
		{"http", "http://" + fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Egress: "127.0.0.2"}).Addr(), true, ""},
		{"socks4", "socks4://" + fakeproxy.NewSOCKS4(t, "127.0.0.3").Addr(), true, ""},
		{"socks5", "socks5://" + fakeproxy.NewSOCKS5(t, "127.0.0.4").Addr(), true, ""},
		{"redirect", "http://" + fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{RedirectTo: "http://login.invalid/"}).Addr(), false, "redirect"},
		{"login page", "http://" + fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Body: "login page"}).Addr(), false, "invalid_probe_response"},
		{"not routing", "http://" + fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{}).Addr(), false, "leaks_client_ip"},
	}
	for _, tc := range cases {
		rec, out := a.do(t, "POST", "/validate", fmt.Sprintf(`{"proxy":%q}`, tc.proxy))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d (%s)", tc.name, rec.Code, rec.Body)
			continue
		}
		if out["alive"] != tc.alive || (tc.why != "" && out["reason"] != tc.why) {
			t.Errorf("%s: response %v, want alive=%v reason=%q", tc.name, out, tc.alive, tc.why)
		}

		host, port, proto, _ := parseProxyString(tc.proxy)
		bg := a.val.Checker().Check(context.Background(), models.NewCandidate(proto, host, port, "t", time.Now()))
		if bg.OK != tc.alive {
			t.Errorf("%s: background result %+v disagrees with /validate", tc.name, bg)
		}
	}
}

func TestValidateSpeaksSOCKS4OnTheWire(t *testing.T) {
	a := newAPI(t, true)
	fx, first := fakeproxy.FirstByte(t)
	go a.do(t, "POST", "/validate", fmt.Sprintf(`{"proxy":"socks4://%s"}`, fx.Addr()))
	select {
	case b := <-first:
		if b != 4 {
			t.Fatalf("SOCKS4 endpoint received first byte %d, want version 4", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS4 endpoint was never contacted")
	}
}

func TestValidateRequestBounds(t *testing.T) {
	a := newAPI(t, true)
	if rec, _ := a.do(t, "POST", "/validate", `{"proxy":"`+strings.Repeat("a", 8<<10)+`"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body: status %d, want 400", rec.Code)
	}
	if rec, _ := a.do(t, "POST", "/validate", `not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad json: status %d, want 400", rec.Code)
	}
	for i := 0; i < maxConcurrentValidations; i++ {
		a.srv.validateSem <- struct{}{}
	}
	if rec, _ := a.do(t, "POST", "/validate", `{"proxy":"http://198.51.100.1:80"}`); rec.Code != http.StatusTooManyRequests {
		t.Errorf("saturated: status %d, want 429", rec.Code)
	}
	if a.srv.httpServer.ReadHeaderTimeout == 0 || a.srv.httpServer.WriteTimeout == 0 || a.srv.httpServer.IdleTimeout == 0 {
		t.Error("server timeouts are not set")
	}
}

func TestHealthReadyAndStats(t *testing.T) {
	a := newAPI(t, true)
	if rec, _ := a.do(t, "GET", "/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("/health = %d", rec.Code)
	}
	rec, out := a.do(t, "GET", "/ready", "")
	if rec.Code != http.StatusServiceUnavailable || out["ready"] != false {
		t.Fatalf("/ready on an empty pool = %d %v", rec.Code, out)
	}

	a.pool.Add(&models.Proxy{ID: "a", Host: "198.51.100.1", Port: 80, Protocol: models.ProtoHTTP, State: models.StateAlive, LastChecked: time.Now()})
	if rec, out := a.do(t, "GET", "/ready", ""); rec.Code != http.StatusOK || out["ready"] != true {
		t.Fatalf("/ready with an alive proxy = %d %v", rec.Code, out)
	}

	rec, out = a.do(t, "GET", "/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/stats = %d", rec.Code)
	}
	poolStats := out["pool"].(map[string]any)
	if poolStats["alive"] != float64(1) || poolStats["discovered"] == nil {
		t.Errorf("/stats pool = %v", poolStats)
	}
	if v := out["validator"].(map[string]any); v["routing_baseline_known"] != true {
		t.Errorf("/stats validator = %v", v)
	}
	if out["storage"] == nil {
		t.Error("/stats has no storage block")
	}

	rec, out = a.do(t, "GET", "/proxy?format=hostport", "")
	if rec.Code != http.StatusOK || out["proxy"] != "198.51.100.1:80" {
		t.Errorf("/proxy = %d %v", rec.Code, out)
	}
}

func TestStatsOmitsUnsetTimes(t *testing.T) {
	a := newAPI(t, true)
	a.srv.storage = fakeStorageStats{}
	rec, _ := a.do(t, "GET", "/stats", "")
	// last_run/next_run keep their 1.4 shape (always present); the new
	// optional timestamps are omitted until set.
	if strings.Contains(rec.Body.String(), `"last_success":"0001-01-01`) {
		t.Fatalf("/stats shows a zero last_success: %s", rec.Body)
	}
}

type fakeStorageStats struct{}

func (fakeStorageStats) Stats() models.StorageStats { return models.StorageStats{} }
