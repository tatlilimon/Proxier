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
		writeGauge(&b, "proxier_validator_checks_total", "Total validation attempts", float64(vs.TotalChecks))
		writeGauge(&b, "proxier_validator_success_total", "Successful validations", float64(vs.SuccessCount))
		writeGauge(&b, "proxier_validator_failure_total", "Failed validations", float64(vs.FailureCount))
		writeGauge(&b, "proxier_validator_success_rate_pct", "Validation success rate", vs.SuccessRate)
		writeGauge(&b, "proxier_validator_avg_latency_ms", "Average validation latency", vs.AvgLatencyMs)

		writeGauge(&b, "proxier_scanner_sources", "Number of active proxy sources", float64(ss.SourcesCount))
		writeGauge(&b, "proxier_scanner_last_fetch_count", "Proxies fetched in last cycle", float64(ss.LastFetchCount))
		writeGauge(&b, "proxier_scanner_discovered_total", "Total unique proxies discovered", float64(ss.TotalDiscovered))
		writeGauge(&b, "proxier_scanner_last_duration_ms", "Last scan cycle duration", float64(ss.LastDurationMs))
		writeGauge(&b, "proxier_scanner_dropped_total", "Proxies dropped due to full channel", float64(ss.Dropped))

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

func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.6f", v)
}
