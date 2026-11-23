package metrics

import (
	"bytes"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil/promlint"
	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/scanner"
	"github.com/tatlilimon/proxier/internal/validator"
)

type fakeStorage struct{}

func (fakeStorage) Stats() models.StorageStats {
	return models.StorageStats{Pending: 3, Failures: 1, LastSuccess: time.Now()}
}

func scrape(t *testing.T) string {
	t.Helper()
	p := pool.NewPool()
	p.Add(&models.Proxy{ID: "a", Host: "198.51.100.1", Port: 80, Protocol: models.ProtoHTTP, State: models.StateAlive, HealthScore: 0.5})
	p.Add(&models.Proxy{ID: "b", Host: "198.51.100.2", Port: 1080, Protocol: models.ProtoSOCKS5, State: models.StateAlive})
	s := scanner.NewScanner([]models.SourceConfig{{URL: "https://lists.example/x.txt", Protocol: models.ProtoHTTP}}, time.Minute, time.Minute, false)

	m := New()
	cfg := models.ValidatorConfig{Workers: 1, TimeoutMs: 1000, ProbeURL: "https://probe.example/ip", KeepaliveIntervalSec: 60, MaxConsecutiveFails: 3}
	v, err := validator.NewValidator(cfg, 10, p, validator.WithBaselineRefresh(0), validator.WithLatencyObserver(m.ObserveLatency))
	if err != nil {
		t.Fatal(err)
	}
	m.Register(p, s, v, fakeStorage{}, time.Now())
	for _, d := range []time.Duration{20 * time.Millisecond, 300 * time.Millisecond, 3 * time.Second} {
		m.ObserveLatency(d)
	}

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

// Audit finding 11: the exposition passes the same lint promtool applies
// (one HELP/TYPE per family, unit and naming rules).
func TestMetricsPassLint(t *testing.T) {
	body := scrape(t)
	problems, err := promlint.New(bytes.NewReader([]byte(body))).Lint()
	if err != nil {
		t.Fatalf("exposition does not parse: %v", err)
	}
	for _, p := range problems {
		t.Errorf("lint: %s: %s", p.Metric, p.Text)
	}
	if n := strings.Count(body, "# HELP proxier_pool_alive_by_protocol "); n != 1 {
		t.Errorf("alive_by_protocol has %d HELP lines, want 1", n)
	}
}

// Audit finding 11: the histogram is built from observations and cumulative.
func TestLatencyHistogramIsRealAndCumulative(t *testing.T) {
	body := scrape(t)
	want := map[string]string{
		`proxier_validator_success_latency_seconds_bucket{le="0.025"}`: "1",
		`proxier_validator_success_latency_seconds_bucket{le="0.5"}`:   "2",
		`proxier_validator_success_latency_seconds_bucket{le="5"}`:     "3",
		`proxier_validator_success_latency_seconds_bucket{le="+Inf"}`:  "3",
		`proxier_validator_success_latency_seconds_count`:              "3",
	}
	prev := -1.0
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if v, ok := want[fields[0]]; ok && fields[1] != v {
			t.Errorf("%s = %s, want %s", fields[0], fields[1], v)
		}
		if strings.HasPrefix(fields[0], "proxier_validator_success_latency_seconds_bucket") {
			var n float64
			if _, err := fmt.Sscan(fields[1], &n); err == nil {
				if n < prev {
					t.Errorf("non-cumulative bucket %s after %v", line, prev)
				}
				prev = n
			}
		}
	}
	for _, name := range []string{"proxier_pool_alive 2", `proxier_pool_alive_by_protocol{protocol="socks5"} 1`, "proxier_storage_pending 3", `proxier_scanner_source_up{source="https://lists.example/x.txt"} 0`} {
		if !strings.Contains(body, name) {
			t.Errorf("missing %q", name)
		}
	}
}
