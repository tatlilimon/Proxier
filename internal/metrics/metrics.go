// Package metrics exposes pool, scanner, and validator counters in
// Prometheus exposition format via an HTTP handler.
package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/scanner"
	"github.com/tatlilimon/proxier/internal/validator"
)

type Metrics struct {
	pool      *pool.Pool
	scanner   *scanner.Scanner
	validator *validator.Validator
	startTime time.Time
}

func New(p *pool.Pool, s *scanner.Scanner, v *validator.Validator, startTime time.Time) *Metrics {
	return &Metrics{pool: p, scanner: s, validator: v, startTime: startTime}
}

func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var b strings.Builder

		ps := m.pool.DetailedStats()
		vs := m.validator.DetailedStats()
		ss := m.scanner.DetailedStats()

		writeGauge(&b, "proxier_pool_total", "Total proxies tracked", float64(ps.Total))
		writeGauge(&b, "proxier_pool_alive", "Alive proxies available for rotation", float64(ps.Alive))
		writeGauge(&b, "proxier_pool_validating", "Proxies currently being validated", float64(ps.Validating))
		writeGauge(&b, "proxier_pool_dead", "Dead proxies", float64(ps.Dead))
		writeGauge(&b, "proxier_pool_dead_last_hour", "Proxies that died in the last hour", float64(ps.DeadLastHour))
		writeGauge(&b, "proxier_pool_avg_health_score", "Average health score of alive proxies", ps.AvgHealthScore)

		for proto, count := range ps.Protocols {
			writeGauge(&b, "proxier_pool_protocol_count", "Alive proxies per protocol", float64(count), "protocol", proto)
		}

		writeGauge(&b, "proxier_validator_workers", "Concurrent validation workers", float64(vs.Workers))
		writeCounter(&b, "proxier_validator_checks_total", "Total number of proxy validations performed", float64(vs.TotalChecks))
		writeCounter(&b, "proxier_validator_success_total", "Total number of successful validations", float64(vs.SuccessCount))
		writeCounter(&b, "proxier_validator_failure_total", "Total number of failed validations", float64(vs.FailureCount))
		writeGauge(&b, "proxier_validator_success_rate_pct", "Validation success rate", vs.SuccessRate)
		writeGauge(&b, "proxier_validator_avg_latency_ms", "Average validation latency", vs.AvgLatencyMs)

		writeHistogram(&b, "proxier_validator_latency_ms", "Validation latency distribution in milliseconds",
			vs.AvgLatencyMs, vs.TotalChecks,
			[]float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000})

		writeGauge(&b, "proxier_scanner_sources", "Number of active proxy sources", float64(ss.SourcesCount))
		writeGauge(&b, "proxier_scanner_last_fetch_count", "Proxies fetched in last cycle", float64(ss.LastFetchCount))
		writeCounter(&b, "proxier_scanner_discovered_total", "Total number of unique proxies discovered", float64(ss.TotalDiscovered))
		writeGauge(&b, "proxier_scanner_last_duration_ms", "Last scan cycle duration", float64(ss.LastDurationMs))
		writeCounter(&b, "proxier_scanner_dropped_total", "Total number of proxies dropped due to full channel", float64(ss.Dropped))

		writeGauge(&b, "proxier_uptime_seconds", "Process uptime in seconds", time.Since(m.startTime).Seconds())

		fmt.Fprint(w, b.String())
	}
}

func writeGauge(b *strings.Builder, name, help string, value float64, labels ...string) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" gauge\n")
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i])
			b.WriteString(`="`)
			b.WriteString(labels[i+1])
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(formatFloat(value))
	b.WriteByte('\n')
}

func writeCounter(b *strings.Builder, name, help string, value float64, labels ...string) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" counter\n")
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i])
			b.WriteString(`="`)
			b.WriteString(labels[i+1])
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(formatFloat(value))
	b.WriteByte('\n')
}

// writeHistogram writes a Prometheus histogram with the given bucket
// boundaries. Since we only have aggregate data (no per-observation
// distribution), all observations are placed in the bucket that contains
// the average value — sum and count are accurate; bucket distribution
// reflects only the mean.
func writeHistogram(b *strings.Builder, name, help string, avgValue float64, count int64, buckets []float64) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" histogram\n")

	fCount := float64(count)
	sum := avgValue * fCount

	placed := false
	for _, le := range buckets {
		b.WriteString(name)
		b.WriteString("_bucket{le=\"")
		b.WriteString(formatBucket(le))
		b.WriteString("\"} ")
		if !placed && avgValue <= le {
			b.WriteString(formatFloat(fCount))
			placed = true
		} else {
			b.WriteString("0")
		}
		b.WriteByte('\n')
	}

	b.WriteString(name)
	b.WriteString("_bucket{le=\"+Inf\"} ")
	b.WriteString(formatFloat(fCount))
	b.WriteByte('\n')

	b.WriteString(name)
	b.WriteString("_sum ")
	b.WriteString(formatFloat(sum))
	b.WriteByte('\n')

	b.WriteString(name)
	b.WriteString("_count ")
	b.WriteString(formatFloat(fCount))
	b.WriteByte('\n')
}

func formatBucket(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}

func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.6f", v)
}
