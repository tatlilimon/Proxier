package validator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tatlilimon/proxier/internal/fakeproxy"
	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/pool"
)

// newTestValidator returns a validator whose probe is a local fixture and
// whose baseline (the client's own address, 127.0.0.1) has been detected.
func newTestValidator(t *testing.T, probe *fakeproxy.Probe, path string, mutate func(*models.ValidatorConfig)) (*Validator, *pool.Pool) {
	t.Helper()
	cfg := models.ValidatorConfig{
		Workers:              2,
		TimeoutMs:            2000,
		ProbeURL:             probe.URL + path,
		KeepaliveIntervalSec: 60,
		MaxConsecutiveFails:  3,
		AllowPrivateProxies:  true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	pl := pool.NewPool()
	v, err := NewValidator(cfg, 100, pl, WithRootCAs(probe.RootCAs()), WithBaselineRefresh(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Checker().DetectBaseline(context.Background()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return v, pl
}

func candidate(fx *fakeproxy.Proxy, proto models.Protocol) models.Proxy {
	return models.NewCandidate(proto, fx.Host, fx.Port, "test", time.Now())
}

func TestCheckAcceptsWorkingProxiesOfEveryProtocol(t *testing.T) {
	for _, withTLS := range []bool{false, true} {
		probe := fakeproxy.NewProbe(t, withTLS)
		v, _ := newTestValidator(t, probe, "/ip", nil)
		cases := []struct {
			name   string
			fx     *fakeproxy.Proxy
			proto  models.Protocol
			egress string
		}{
			{"http", fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Egress: "127.0.0.2"}), models.ProtoHTTP, "127.0.0.2"},
			{"socks4", fakeproxy.NewSOCKS4(t, "127.0.0.3"), models.ProtoSOCKS4, "127.0.0.3"},
			{"socks5", fakeproxy.NewSOCKS5(t, "127.0.0.4"), models.ProtoSOCKS5, "127.0.0.4"},
		}
		for _, tc := range cases {
			res := v.Checker().Check(context.Background(), candidate(tc.fx, tc.proto))
			if !res.OK {
				t.Errorf("tls=%v %s: result = %+v, want OK", withTLS, tc.name, res)
				continue
			}
			if len(res.Origins) != 1 || res.Origins[0] != tc.egress {
				t.Errorf("tls=%v %s: origins = %v, want [%s]", withTLS, tc.name, res.Origins, tc.egress)
			}
		}
	}
}

// Audit finding 3: invalid or leaking probe answers must not count as working.
func TestCheckRejectsInvalidAndLeakingAnswers(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, _ := newTestValidator(t, probe, "/ip", nil)

	for _, tc := range []struct {
		body string
		want Reason
	}{
		{"<html>captive portal</html>", ReasonInvalidResponse},
		{`{}`, ReasonInvalidResponse},
		{`{"origin":"not-an-ip"}`, ReasonInvalidResponse},
		{`{"origin":"127.0.0.1"}`, ReasonLeak},
	} {
		fx := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Body: tc.body})
		res := v.Checker().Check(context.Background(), candidate(fx, models.ProtoHTTP))
		if res.OK || res.Reason != tc.want {
			t.Errorf("body %q: result = %+v, want reason %s", tc.body, res, tc.want)
		}
	}

	// A transparent proxy forwards the client's address: the probe lists
	// "127.0.0.1, 127.0.0.2" and the client address gives it away.
	leaky := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Egress: "127.0.0.2", ForwardClient: true})
	if res := v.Checker().Check(context.Background(), candidate(leaky, models.ProtoHTTP)); res.Reason != ReasonLeak {
		t.Errorf("transparent proxy: result = %+v, want %s", res, ReasonLeak)
	}

	// The audit's multi-origin case against an explicit baseline.
	v.Checker().Baseline().Set([]string{"192.0.2.1"})
	multi := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Body: `{"origin":"192.0.2.1, 198.51.100.2"}`})
	if res := v.Checker().Check(context.Background(), candidate(multi, models.ProtoHTTP)); res.Reason != ReasonLeak {
		t.Errorf("multi-origin leak: result = %+v, want %s", res, ReasonLeak)
	}
}

func TestCheckRejectsRedirect(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, _ := newTestValidator(t, probe, "/ip", nil)
	fx := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{RedirectTo: "http://login.invalid/"})
	if res := v.Checker().Check(context.Background(), candidate(fx, models.ProtoHTTP)); res.Reason != ReasonRedirect {
		t.Fatalf("result = %+v, want %s", res, ReasonRedirect)
	}
}

// Audit finding 2: TLS is verified, both to an https proxy and end to end
// through a proxy that intercepts CONNECT.
func TestCheckRejectsUntrustedTLS(t *testing.T) {
	probe := fakeproxy.NewProbe(t, true)
	v, _ := newTestValidator(t, probe, "/ip", nil)

	httpsProxy := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{TLS: true, Egress: "127.0.0.2"})
	if res := v.Checker().Check(context.Background(), candidate(httpsProxy, models.ProtoHTTPS)); res.OK || res.Reason != ReasonTLS {
		t.Errorf("https proxy with untrusted certificate: result = %+v, want %s", res, ReasonTLS)
	}

	mitm := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{MITM: true})
	if res := v.Checker().Check(context.Background(), candidate(mitm, models.ProtoHTTP)); res.OK || res.Reason != ReasonTLS {
		t.Errorf("intercepting proxy: result = %+v, want %s", res, ReasonTLS)
	}
}

func TestCheckWithUnknownBaselineIsIndeterminate(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	cfg := models.ValidatorConfig{Workers: 1, TimeoutMs: 2000, ProbeURL: probe.URL + "/ip", KeepaliveIntervalSec: 60, MaxConsecutiveFails: 3, AllowPrivateProxies: true}
	pl := pool.NewPool()
	v, err := NewValidator(cfg, 10, pl, WithBaselineRefresh(0))
	if err != nil {
		t.Fatal(err)
	}
	fx := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Egress: "127.0.0.2"})
	c := candidate(fx, models.ProtoHTTP)
	pl.Merge([]models.Proxy{c})

	res := v.Checker().Check(context.Background(), c)
	if !res.Indeterminate || res.Reason != ReasonRoutingUnverified {
		t.Fatalf("result = %+v, want indeterminate %s", res, ReasonRoutingUnverified)
	}
	v.record(c, res)
	got, _ := pl.Get(c.ID)
	if got.State != models.StateDiscovered || got.ConsecutiveFail != 0 || got.NextCheck.IsZero() {
		t.Errorf("indeterminate result changed the record: %+v", got)
	}
	if s := v.DetailedStats(); s.TotalChecks != 0 || s.Indeterminate != 1 {
		t.Errorf("stats = %+v, want 0 checks and 1 indeterminate", s)
	}
}

// Audit finding 4: a SOCKS5 proxy that never completes its handshake must
// not keep the dial alive after the deadline.
func TestSOCKS5DialHonoursCancellation(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, _ := newTestValidator(t, probe, "/ip", nil)
	stall := fakeproxy.NewStall(t)

	tr, err := v.Checker().transport(candidate(stall, models.ProtoSOCKS5))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := tr.DialContext(ctx, "tcp", "example.com:80")
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled SOCKS5 proxy returned a connection")
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 DialContext still blocked after the context deadline")
	}

	start := time.Now()
	res := v.Checker().Check(context.Background(), candidate(stall, models.ProtoSOCKS4))
	if res.OK || res.Reason != ReasonTimeout {
		t.Errorf("stalled SOCKS4 proxy: result = %+v, want %s", res, ReasonTimeout)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("stalled check took %s, want about the 2 s timeout", elapsed)
	}
}

func TestCanceledCheckChangesNothing(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, pl := newTestValidator(t, probe, "/ip", nil)
	stall := fakeproxy.NewStall(t)
	c := candidate(stall, models.ProtoSOCKS5)
	pl.Merge([]models.Proxy{c})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	res := v.Checker().Check(ctx, c)
	if !res.Indeterminate || res.Reason != ReasonCanceled {
		t.Fatalf("result = %+v, want indeterminate %s", res, ReasonCanceled)
	}
	v.record(c, res)
	got, _ := pl.Get(c.ID)
	if got.State != models.StateDiscovered || got.ConsecutiveFail != 0 || v.DetailedStats().TotalChecks != 0 {
		t.Errorf("a cancelled check changed state: record %+v stats %+v", got, v.DetailedStats())
	}
}

func TestCheckRefusesPrivateAddressesByDefault(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, _ := newTestValidator(t, probe, "/ip", func(c *models.ValidatorConfig) { c.AllowPrivateProxies = false })
	fx := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Egress: "127.0.0.2"})
	if res := v.Checker().Check(context.Background(), candidate(fx, models.ProtoHTTP)); res.Reason != ReasonDisallowedAddress {
		t.Fatalf("result = %+v, want %s", res, ReasonDisallowedAddress)
	}
	if fx.Handled.Load() != 0 {
		t.Fatal("the refused proxy was contacted")
	}
}

func okResult() Result {
	return Result{OK: true, Latency: 50 * time.Millisecond, Origins: []string{"198.51.100.2"}}
}
func failResult() Result { return Result{Reason: ReasonConnect} }

func addRecord(t *testing.T, pl *pool.Pool, rec models.Proxy) models.Proxy {
	t.Helper()
	pl.Add(&rec)
	got, _ := pl.Get(rec.ID)
	return *got
}

// Audit finding 12: a failure resets the success streak.
func TestSuccessStreakResetsOnFailure(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, pl := newTestValidator(t, probe, "/ip", nil)
	p := addRecord(t, pl, models.NewCandidate(models.ProtoHTTP, "198.51.100.7", 8080, "t", time.Now()))
	for i := 0; i < 3; i++ {
		v.record(p, okResult())
	}
	v.record(p, failResult())
	v.record(p, okResult())
	got, _ := pl.Get(p.ID)
	if got.ConsecutiveOK != 1 {
		t.Fatalf("after success x3, failure, success: streak = %d, want 1", got.ConsecutiveOK)
	}
	if s := v.DetailedStats(); s.AvgLatencyMs != 50 {
		t.Errorf("avg latency = %v, want 50 (successful checks only)", s.AvgLatencyMs)
	}
}

// Audit finding 1: after enough failures the proxy is DEAD, counted as dead
// and never selected.
func TestDeadProxyIsNotSelectableAndCountersAgree(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, pl := newTestValidator(t, probe, "/ip", nil)
	p := addRecord(t, pl, models.NewCandidate(models.ProtoHTTP, "198.51.100.7", 8080, "t", time.Now()))
	v.record(p, okResult())
	if _, err := pl.GetRandom(pool.PoolFilter{}); err != nil {
		t.Fatal("alive proxy not selectable")
	}
	for i := 0; i < 3; i++ {
		v.record(p, failResult())
	}
	got, _ := pl.Get(p.ID)
	if got.State != models.StateDead {
		t.Fatalf("state = %s, want DEAD", got.State)
	}
	if sel, err := pl.GetRandom(pool.PoolFilter{}); err == nil {
		t.Fatalf("selected %s proxy after 3 failures", sel.State)
	}
	stats := pl.DetailedStats()
	census := pl.Census()
	if stats.Dead != 1 || stats.Alive != 0 || census[models.StateDead] != 1 {
		t.Fatalf("stats %+v census %v, want one dead and nothing alive", stats, census)
	}
}

// Audit finding 8: rediscovery keeps history.
func TestRediscoveryKeepsHistory(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, pl := newTestValidator(t, probe, "/ip", nil)
	rec := models.NewCandidate(models.ProtoHTTP, "198.51.100.7", 8080, "t", time.Now().Add(-24*time.Hour))
	rec.ConsecutiveOK = 8
	p := addRecord(t, pl, rec)
	v.record(p, okResult())

	pl.Merge([]models.Proxy{models.NewCandidate(models.ProtoHTTP, "198.51.100.7", 8080, "t", time.Now())})
	v.record(p, okResult())

	got, _ := pl.Get(p.ID)
	if got.ConsecutiveOK != 10 || time.Since(got.FirstSeen) < time.Hour {
		t.Fatalf("history lost: streak=%d first_seen=%s", got.ConsecutiveOK, got.FirstSeen)
	}
}

func TestFailureBackoffAndDeadRetries(t *testing.T) {
	v := &Validator{keepaliveInterval: 120 * time.Second, maxFails: 3}
	prev := time.Duration(0)
	for fails := 1; fails <= 6; fails++ {
		d := v.retryDelay(fails)
		if d < prev || d > v.keepaliveInterval {
			t.Errorf("retryDelay(%d) = %s (previous %s), want non-decreasing and at most the keepalive interval", fails, d, prev)
		}
		prev = d
	}

	now := time.Now()
	rec := &models.Proxy{State: models.StateValidating, ConsecutiveFail: 2}
	v.applyResult(rec, failResult(), now)
	if rec.State != models.StateDead || !rec.DiedAt.Equal(now) || !rec.NextCheck.Equal(now.Add(120*time.Second)) {
		t.Fatalf("death: %+v", rec)
	}
	var retries int
	for i := 0; i < 10 && !rec.NextCheck.IsZero(); i++ {
		v.applyResult(rec, failResult(), now)
		retries++
	}
	if retries != 3 || !rec.NextCheck.IsZero() {
		t.Errorf("dead retries = %d (next %v), want 3 spaced retries and then none", retries, rec.NextCheck)
	}
	v.applyResult(rec, okResult(), now)
	if rec.State != models.StateAlive || !rec.DiedAt.IsZero() || rec.ConsecutiveFail != 0 {
		t.Errorf("recovered dead proxy: %+v", rec)
	}
}

// Audit finding 6: one destination per record and cycle, and nothing is
// scheduled twice while in flight.
func TestScheduleSendsEachRecordToExactlyOneQueue(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, pl := newTestValidator(t, probe, "/ip", func(c *models.ValidatorConfig) {
		c.KeepaliveWorkers = 1
		c.KeepaliveUseMainChannel = true
	})
	alive := models.NewCandidate(models.ProtoHTTP, "198.51.100.7", 8080, "t", time.Now())
	alive.State = models.StateAlive
	pl.Add(&alive)

	v.schedule()
	v.schedule()
	if n := len(v.queue) + len(v.keepaliveQueue); n != 1 {
		t.Fatalf("queued %d times (main %d, keepalive %d), want once", n, len(v.queue), len(v.keepaliveQueue))
	}
	if len(v.keepaliveQueue) != 1 {
		t.Fatal("an ALIVE recheck should go to the dedicated keepalive worker first")
	}
}

// A large failing backlog must not starve ALIVE rechecks.
func TestScheduleRechecksAliveBeforeBacklog(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	cfg := models.ValidatorConfig{Workers: 1, TimeoutMs: 2000, ProbeURL: probe.URL + "/ip", KeepaliveIntervalSec: 60, MaxConsecutiveFails: 3, AllowPrivateProxies: true}
	pl := pool.NewPool()
	v, err := NewValidator(cfg, 5, pl, WithBaselineRefresh(0))
	if err != nil {
		t.Fatal(err)
	}
	var backlog []models.Proxy
	for i := 0; i < 50; i++ {
		backlog = append(backlog, models.NewCandidate(models.ProtoHTTP, "198.51.100.7", 1000+i, "t", time.Now()))
	}
	pl.Merge(backlog)
	alive := models.NewCandidate(models.ProtoHTTP, "198.51.100.8", 8080, "t", time.Now())
	alive.State = models.StateAlive
	pl.Add(&alive)

	v.schedule()
	first := <-v.queue
	if first.ID != alive.ID {
		t.Fatalf("first scheduled = %s, want the ALIVE recheck", first.URL())
	}
}

// Audit acceptance 1: race-free under concurrent validation, scanning,
// selection, persistence and statistics; counters equal the census.
func TestConcurrentValidationKeepsCountersConsistent(t *testing.T) {
	probe := fakeproxy.NewProbe(t, false)
	v, pl := newTestValidator(t, probe, "/ip", func(c *models.ValidatorConfig) { c.Workers = 4; c.KeepaliveIntervalSec = 1 })
	v.scheduleInterval = 5 * time.Millisecond
	v.keepaliveInterval = 30 * time.Millisecond

	good := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Egress: "127.0.0.2"})
	bad := fakeproxy.NewHTTPProxy(t, fakeproxy.HTTPOptions{Body: "{}"})
	cands := []models.Proxy{candidate(good, models.ProtoHTTP), candidate(bad, models.ProtoHTTP)}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { v.Run(ctx) })
	wg.Go(func() {
		for ctx.Err() == nil {
			pl.Merge(cands)
			pl.GetN(10, "health_score", pool.PoolFilter{})
			pl.GetRandom(pool.PoolFilter{})
			if up, del, ack := pl.DirtySnapshot(); len(up)+len(del) > 0 {
				pl.Acknowledge(ack)
			}
			pl.DetailedStats()
			v.DetailedStats()
			time.Sleep(time.Millisecond)
		}
	})
	time.Sleep(500 * time.Millisecond)
	cancel()
	wg.Wait()

	stats, census := pl.DetailedStats(), pl.Census()
	if stats.Alive != census[models.StateAlive] || stats.Dead != census[models.StateDead] ||
		stats.Validating != census[models.StateValidating] || stats.Discovered != census[models.StateDiscovered] {
		t.Fatalf("counters %+v disagree with census %v", stats, census)
	}
	g, _ := pl.Get(cands[0].ID)
	b, _ := pl.Get(cands[1].ID)
	if g.State != models.StateAlive || b.State == models.StateAlive {
		t.Fatalf("good=%s bad=%s, want good ALIVE and bad not ALIVE", g.State, b.State)
	}
}

func TestParseOrigins(t *testing.T) {
	got, err := ParseOrigins([]byte(`{"origin":"198.51.100.2, ::ffff:203.0.113.1, 198.51.100.2"}`))
	if err != nil || len(got) != 2 || got[0] != "198.51.100.2" || got[1] != "203.0.113.1" {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := ParseOrigins([]byte(`{"ip":"2001:db8::1"}`)); err != nil || got[0] != "2001:db8::1" {
		t.Fatalf("ip field: %v, %v", got, err)
	}
	for _, body := range []string{``, `[]`, `{"origin":""}`, `{"origin":"1.2.3.4, nope"}`} {
		if _, err := ParseOrigins([]byte(body)); err == nil {
			t.Errorf("ParseOrigins(%q) accepted", body)
		}
	}
}

func TestNewValidatorRejectsBadSettings(t *testing.T) {
	base := models.ValidatorConfig{Workers: 1, TimeoutMs: 1000, ProbeURL: "https://httpbin.org/ip", KeepaliveIntervalSec: 60, MaxConsecutiveFails: 3}
	for name, mutate := range map[string]func(*models.ValidatorConfig){
		"no workers":   func(c *models.ValidatorConfig) { c.Workers = 0 },
		"bad probe":    func(c *models.ValidatorConfig) { c.ProbeURL = "ftp://x" },
		"no keepalive": func(c *models.ValidatorConfig) { c.KeepaliveIntervalSec = 0 },
		"no timeout":   func(c *models.ValidatorConfig) { c.TimeoutMs = 0 },
		"missing CA":   func(c *models.ValidatorConfig) { c.ExtraCAFile = "/nonexistent/ca.pem" },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := NewValidator(cfg, 10, pool.NewPool()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewValidator(base, 10, pool.NewPool()); err != nil {
		t.Errorf("valid settings rejected: %v", err)
	}

}
