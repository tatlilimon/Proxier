// Package metrics exposes pool, scanner, validator and storage state in the
// Prometheus exposition format, using the official client library: each
// metric family is defined once, and the latency histogram records actual
// observations.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/scanner"
	"github.com/tatlilimon/proxier/internal/validator"
)

// StorageStats reports persistence health.
type StorageStats interface {
	Stats() models.StorageStats
}

// latencyBuckets cover 5 ms to 10 s.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Metrics owns the registry. Create it with New, pass ObserveLatency to the
// validator, then call Register once the components exist.
type Metrics struct {
	reg     *prometheus.Registry
	latency prometheus.Histogram
}

// New creates the registry and the latency histogram.
func New() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		latency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "proxier_validator_success_latency_seconds",
			Help:    "Latency of successful proxy checks.",
			Buckets: latencyBuckets,
		}),
	}
	m.reg.MustRegister(m.latency)
	return m
}

// ObserveLatency records the latency of one successful check.
func (m *Metrics) ObserveLatency(d time.Duration) {
	m.latency.Observe(d.Seconds())
}

// Register adds the state collector for the running components.
func (m *Metrics) Register(p *pool.Pool, s *scanner.Scanner, v *validator.Validator, st StorageStats, startTime time.Time) {
	m.reg.MustRegister(&collector{pool: p, scanner: s, validator: v, storage: st, start: startTime})
}

// Registry returns the registry (for tests).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// Handler serves the registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

var (
	poolTotal      = desc("proxier_pool_records", "Proxy records of any state.")
	poolAlive      = desc("proxier_pool_alive", "Proxies in rotation (ALIVE).")
	poolValidating = desc("proxier_pool_validating", "Proxies out of rotation waiting for another check (VALIDATING).")
	poolDead       = desc("proxier_pool_dead", "Dead proxies.")
	poolDiscovered = desc("proxier_pool_discovered", "Candidates waiting for their first check.")
	poolDeadHour   = desc("proxier_pool_dead_last_hour", "Proxies that became dead in the last hour.")
	poolAvgHealth  = desc("proxier_pool_avg_health_score", "Average health score of alive proxies.")
	poolProtocol   = desc("proxier_pool_alive_by_protocol", "Alive proxies per protocol.", "protocol")

	valWorkers      = desc("proxier_validator_workers", "Validation workers (main and keepalive).")
	valChecks       = desc("proxier_validator_checks_total", "Completed proxy checks (successes and failures).")
	valSuccess      = desc("proxier_validator_success_total", "Successful proxy checks.")
	valFailure      = desc("proxier_validator_failure_total", "Failed proxy checks.")
	valReasons      = desc("proxier_validator_failures_by_reason_total", "Failed proxy checks by reason.", "reason")
	valIndeterm     = desc("proxier_validator_indeterminate_total", "Checks that could not be judged because the routing baseline was unknown.")
	valRate         = desc("proxier_validator_success_rate_pct", "Share of completed checks that succeeded, in percent.")
	valAvgLatency   = desc("proxier_validator_avg_latency_seconds", "Mean latency of successful checks since start.")
	valInFlight     = desc("proxier_validator_in_flight", "Checks running now.")
	valQueue        = desc("proxier_validator_queue_depth", "Checks scheduled but not started.")
	valBaselineKnow = desc("proxier_validator_routing_baseline_known", "1 when the client's own address is known, so leaks can be detected.")

	scanSources     = desc("proxier_scanner_sources", "Configured proxy sources.")
	scanSourcesOK   = desc("proxier_scanner_sources_ok", "Sources whose last fetch succeeded.")
	scanSourceUp    = desc("proxier_scanner_source_up", "1 when the source's last fetch succeeded.", "source")
	scanSourceLast  = desc("proxier_scanner_source_last_success_timestamp_seconds", "Time of the source's last successful fetch.", "source")
	scanSourceCount = desc("proxier_scanner_source_last_fetched", "Candidates parsed from the source's last fetch.", "source")
	scanFetch       = desc("proxier_scanner_last_fetched", "Candidates parsed in the last cycle, before deduplication.")
	scanNew         = desc("proxier_scanner_last_new", "Records the last cycle added to the pool.")
	scanDiscovered  = desc("proxier_scanner_discovered_total", "Unique proxy records added to the pool.")
	scanRejected    = desc("proxier_scanner_rejected_total", "Candidates refused by the address policy.")
	scanDropped     = desc("proxier_scanner_dropped_total", "Candidates dropped before validation (always 0; kept for compatibility).")
	scanDuration    = desc("proxier_scanner_last_duration_seconds", "Duration of the last scan cycle.")
	scanLastRun     = desc("proxier_scanner_last_run_timestamp_seconds", "Start time of the last scan cycle.")

	storePending  = desc("proxier_storage_pending", "Changes not yet written to storage.")
	storeFailures = desc("proxier_storage_failures_total", "Failed storage writes.")
	storeLast     = desc("proxier_storage_last_success_timestamp_seconds", "Time of the last successful storage write.")

	uptime = desc("proxier_uptime_seconds", "Process uptime.")
)

// collector reads every value at scrape time.
type collector struct {
	pool      *pool.Pool
	scanner   *scanner.Scanner
	validator *validator.Validator
	storage   StorageStats
	start     time.Time
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		poolTotal, poolAlive, poolValidating, poolDead, poolDiscovered, poolDeadHour, poolAvgHealth, poolProtocol,
		valWorkers, valChecks, valSuccess, valFailure, valReasons, valIndeterm, valRate, valAvgLatency,
		valInFlight, valQueue, valBaselineKnow,
		scanSources, scanSourcesOK, scanSourceUp, scanSourceLast, scanSourceCount, scanFetch, scanNew,
		scanDiscovered, scanRejected, scanDropped, scanDuration, scanLastRun,
		storePending, storeFailures, storeLast, uptime,
	} {
		ch <- d
	}
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	counter := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, labels...)
	}
	ts := func(t time.Time) float64 {
		if t.IsZero() {
			return 0
		}
		return float64(t.UnixNano()) / 1e9
	}

	ps := c.pool.DetailedStats()
	gauge(poolTotal, float64(ps.Total))
	gauge(poolAlive, float64(ps.Alive))
	gauge(poolValidating, float64(ps.Validating))
	gauge(poolDead, float64(ps.Dead))
	gauge(poolDiscovered, float64(ps.Discovered))
	gauge(poolDeadHour, float64(ps.DeadLastHour))
	gauge(poolAvgHealth, ps.AvgHealthScore)
	for _, proto := range models.ProxyProtocols {
		gauge(poolProtocol, float64(ps.Protocols[string(proto)]), string(proto))
	}

	vs := c.validator.DetailedStats()
	gauge(valWorkers, float64(vs.Workers))
	counter(valChecks, float64(vs.TotalChecks))
	counter(valSuccess, float64(vs.SuccessCount))
	counter(valFailure, float64(vs.FailureCount))
	for reason, n := range c.validator.FailureCounts() {
		counter(valReasons, float64(n), string(reason))
	}
	counter(valIndeterm, float64(vs.Indeterminate))
	gauge(valRate, vs.SuccessRate)
	gauge(valAvgLatency, vs.AvgLatencyMs/1000)
	gauge(valInFlight, float64(vs.InFlight))
	gauge(valQueue, float64(vs.QueueDepth))
	known := 0.0
	if vs.RoutingBaselineKnown {
		known = 1
	}
	gauge(valBaselineKnow, known)

	ss := c.scanner.DetailedStats()
	gauge(scanSources, float64(ss.SourcesCount))
	gauge(scanSourcesOK, float64(ss.SourcesOK))
	for _, src := range ss.Sources {
		up := 0.0
		if src.OK {
			up = 1
		}
		gauge(scanSourceUp, up, src.URL)
		gauge(scanSourceLast, ts(src.LastSuccess), src.URL)
		gauge(scanSourceCount, float64(src.LastCount), src.URL)
	}
	gauge(scanFetch, float64(ss.LastFetchCount))
	gauge(scanNew, float64(ss.LastNewCount))
	counter(scanDiscovered, float64(ss.TotalDiscovered))
	counter(scanRejected, float64(ss.Rejected))
	counter(scanDropped, float64(ss.Dropped))
	gauge(scanDuration, float64(ss.LastDurationMs)/1000)
	gauge(scanLastRun, ts(ss.LastRun))

	if c.storage != nil {
		st := c.storage.Stats()
		gauge(storePending, float64(st.Pending))
		counter(storeFailures, float64(st.Failures))
		gauge(storeLast, ts(st.LastSuccess))
	}

	gauge(uptime, time.Since(c.start).Seconds())
}
