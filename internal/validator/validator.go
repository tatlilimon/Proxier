// Package validator checks proxies and keeps their state in the pool up to
// date.
//
// Scheduling: every record carries an explicit NextCheck time. A scheduler
// asks the pool for due records (most important first: ALIVE rechecks, then
// previously working proxies, new candidates, never-working retries and DEAD
// retries), marks them in flight and hands them to the workers. A record is
// never checked twice at the same time and never sent to two queues, so
// results cannot overlap or arrive stale. Results are applied to the pool's
// canonical record, which preserves its history.
package validator

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
)

// Pool is the part of pool.Pool the validator depends on.
type Pool interface {
	Update(id string, fn func(rec *models.Proxy)) bool
	Due(now time.Time, limit int, skip func(id string) bool) []*models.Proxy
}

// Option customises a Validator.
type Option func(*Validator)

// WithRootCAs replaces the trusted roots (tests use their own CA).
func WithRootCAs(roots *x509.CertPool) Option { return func(v *Validator) { v.rootCAs = roots } }

// WithScheduleInterval sets how often due records are scheduled.
func WithScheduleInterval(d time.Duration) Option {
	return func(v *Validator) { v.scheduleInterval = d }
}

// WithBaselineRefresh sets how often a known routing baseline is refreshed.
// Zero disables baseline detection (the caller sets it).
func WithBaselineRefresh(d time.Duration) Option {
	return func(v *Validator) { v.baselineRefresh = d }
}

// WithLatencyObserver receives the latency of every successful check.
func WithLatencyObserver(fn func(time.Duration)) Option {
	return func(v *Validator) { v.observer = fn }
}

// WithUserAgent sets the User-Agent of probe requests.
func WithUserAgent(ua string) Option { return func(v *Validator) { v.userAgent = ua } }

// Validator consumes due records, tests them and applies the results.
type Validator struct {
	checker           *Checker
	pool              Pool
	workers           int
	keepaliveWorkers  int
	keepaliveOverflow bool
	maxFails          int
	keepaliveInterval time.Duration
	scheduleInterval  time.Duration
	baselineRefresh   time.Duration
	rootCAs           *x509.CertPool
	userAgent         string
	observer          func(time.Duration)
	now               func() time.Time

	queue          chan models.Proxy
	keepaliveQueue chan models.Proxy

	inflightMu sync.Mutex
	inflight   map[string]struct{}
	inFlightN  atomic.Int64

	checked          atomic.Int64
	successCount     atomic.Int64
	failureCount     atomic.Int64
	indeterminate    atomic.Int64
	successLatencyMs atomic.Int64
	reasons          map[Reason]*atomic.Int64
}

// NewValidator creates a Validator. queueSize is the capacity of the check
// queue between the scheduler and the workers.
func NewValidator(cfg models.ValidatorConfig, queueSize int, pool Pool, opts ...Option) (*Validator, error) {
	v := &Validator{
		pool:              pool,
		workers:           cfg.Workers,
		keepaliveWorkers:  cfg.KeepaliveWorkers,
		keepaliveOverflow: cfg.KeepaliveUseMainChannel,
		maxFails:          cfg.MaxConsecutiveFails,
		keepaliveInterval: time.Duration(cfg.KeepaliveIntervalSec) * time.Second,
		scheduleInterval:  time.Second,
		baselineRefresh:   30 * time.Minute,
		now:               time.Now,
		inflight:          make(map[string]struct{}),
		reasons:           make(map[Reason]*atomic.Int64, len(FailureReasons)),
	}
	for _, r := range FailureReasons {
		v.reasons[r] = new(atomic.Int64)
	}
	if cfg.ExtraCAFile != "" {
		roots, err := loadRoots(cfg.ExtraCAFile)
		if err != nil {
			return nil, err
		}
		v.rootCAs = roots
	}
	for _, o := range opts {
		o(v)
	}
	if v.workers < 1 {
		return nil, fmt.Errorf("validator needs at least one worker, got %d", v.workers)
	}
	if v.maxFails < 1 {
		v.maxFails = 1
	}
	if v.keepaliveInterval <= 0 {
		return nil, fmt.Errorf("keepalive interval must be positive")
	}
	if queueSize < 1 {
		queueSize = 1
	}

	checker, err := NewChecker(CheckerConfig{
		Timeout:      time.Duration(cfg.TimeoutMs) * time.Millisecond,
		ProbeURL:     cfg.ProbeURL,
		RootCAs:      v.rootCAs,
		AllowPrivate: cfg.AllowPrivateProxies,
		UserAgent:    v.userAgent,
	})
	if err != nil {
		return nil, err
	}
	v.checker = checker

	v.queue = make(chan models.Proxy, queueSize)
	if v.keepaliveWorkers > 0 {
		v.keepaliveQueue = make(chan models.Proxy, queueSize)
	}
	return v, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading extra CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("extra CA file %s contains no PEM certificates", path)
	}
	return roots, nil
}

// Checker returns the side-effect-free check engine (used by POST /validate).
func (v *Validator) Checker() *Checker { return v.checker }

// Run starts the workers, the scheduler and the routing-baseline loop and
// blocks until ctx is cancelled and all of them have returned. A check
// interrupted by cancellation is not counted and changes nothing.
func (v *Validator) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := 0; i < v.workers; i++ {
		wg.Go(func() { v.work(ctx, v.queue) })
	}
	for i := 0; i < v.keepaliveWorkers; i++ {
		wg.Go(func() { v.work(ctx, v.keepaliveQueue) })
	}
	if v.baselineRefresh > 0 {
		wg.Go(func() { v.checker.RunBaseline(ctx, v.baselineRefresh) })
	}
	wg.Go(func() { v.scheduleLoop(ctx) })
	wg.Wait()
	return nil
}

func (v *Validator) work(ctx context.Context, q <-chan models.Proxy) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-q:
			v.process(ctx, p)
		}
	}
}

func (v *Validator) scheduleLoop(ctx context.Context) {
	ticker := time.NewTicker(v.scheduleInterval)
	defer ticker.Stop()
	for {
		v.schedule()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// schedule moves due records into the queues while they have room. Each
// record goes to exactly one queue: ALIVE rechecks to the dedicated
// keepalive workers when they exist (overflowing into the main queue only
// when keepalive_use_main_channel is set), everything else to the main queue.
func (v *Validator) schedule() {
	free := cap(v.queue) - len(v.queue)
	if v.keepaliveQueue != nil {
		free += cap(v.keepaliveQueue) - len(v.keepaliveQueue)
	}
	if free <= 0 {
		return
	}
	for _, p := range v.pool.Due(v.now(), free, v.isInflight) {
		if !v.markInflight(p.ID) {
			continue
		}
		if !v.enqueue(*p) {
			v.unmarkInflight(p.ID)
		}
	}
}

func (v *Validator) enqueue(p models.Proxy) bool {
	if p.State == models.StateAlive && v.keepaliveQueue != nil {
		select {
		case v.keepaliveQueue <- p:
			return true
		default:
			if !v.keepaliveOverflow {
				return false
			}
		}
	}
	select {
	case v.queue <- p:
		return true
	default:
		return false
	}
}

func (v *Validator) isInflight(id string) bool {
	v.inflightMu.Lock()
	defer v.inflightMu.Unlock()
	_, ok := v.inflight[id]
	return ok
}

func (v *Validator) markInflight(id string) bool {
	v.inflightMu.Lock()
	defer v.inflightMu.Unlock()
	if _, ok := v.inflight[id]; ok {
		return false
	}
	v.inflight[id] = struct{}{}
	return true
}

func (v *Validator) unmarkInflight(id string) {
	v.inflightMu.Lock()
	defer v.inflightMu.Unlock()
	delete(v.inflight, id)
}

// process checks one record and applies the result.
func (v *Validator) process(ctx context.Context, p models.Proxy) {
	v.inFlightN.Add(1)
	defer v.inFlightN.Add(-1)
	defer v.unmarkInflight(p.ID)

	res := v.checker.Check(ctx, p)
	v.record(p, res)
}

// record updates the statistics and applies res to the canonical record.
func (v *Validator) record(p models.Proxy, res Result) {
	now := v.now()
	if res.Indeterminate {
		if res.Reason == ReasonCanceled {
			return
		}
		v.indeterminate.Add(1)
		retry := min(v.keepaliveInterval, 30*time.Second)
		v.pool.Update(p.ID, func(rec *models.Proxy) { rec.NextCheck = now.Add(retry) })
		return
	}

	v.checked.Add(1)
	if res.OK {
		v.successCount.Add(1)
		v.successLatencyMs.Add(res.Latency.Milliseconds())
		if v.observer != nil {
			v.observer(res.Latency)
		}
	} else {
		v.failureCount.Add(1)
		if c, ok := v.reasons[res.Reason]; ok {
			c.Add(1)
		}
		slog.Debug("validator check failed", "proxy", p.URL(), "reason", string(res.Reason), "detail", res.Detail)
	}

	v.pool.Update(p.ID, func(rec *models.Proxy) {
		prev := rec.State
		v.applyResult(rec, res, now)
		if rec.State == models.StateDead && prev != models.StateDead {
			slog.Info("validator proxy marked dead", "proxy", rec.URL(), "consecutive_fails", rec.ConsecutiveFail)
		}
	})
}

// applyResult is the state machine for one check result.
//
//	success: ALIVE, streak+1, failures reset, next check after the keepalive interval
//	failure: streak reset; VALIDATING with backoff until max_consecutive_fails,
//	         then DEAD with a few spaced retries
func (v *Validator) applyResult(rec *models.Proxy, res Result, now time.Time) {
	rec.LastChecked = now
	if res.OK {
		rec.LatencyMs = int(res.Latency.Milliseconds())
		rec.ConsecutiveOK++
		rec.ConsecutiveFail = 0
		rec.State = models.StateAlive
		rec.LastSuccess = now
		rec.DiedAt = time.Time{}
		rec.HealthScore = v.calcHealthScore(rec)
		rec.NextCheck = now.Add(v.keepaliveInterval)
		return
	}

	rec.ConsecutiveFail++
	rec.ConsecutiveOK = 0
	switch {
	case rec.State == models.StateDead:
		rec.HealthScore = 0
		rec.NextCheck = v.deadRetryAt(rec, now)
	case rec.ConsecutiveFail >= v.maxFails:
		rec.State = models.StateDead
		rec.DiedAt = now
		rec.HealthScore = 0
		rec.NextCheck = v.deadRetryAt(rec, now)
	default:
		rec.State = models.StateValidating
		rec.HealthScore = v.calcHealthScore(rec)
		rec.NextCheck = now.Add(v.retryDelay(rec.ConsecutiveFail))
	}
}

// retryDelay is the backoff before rechecking a failing (not yet dead) proxy:
// keepalive/8 (clamped to 10 ms–15 s), doubling per failure, never above the
// keepalive interval.
func (v *Validator) retryDelay(fails int) time.Duration {
	base := min(max(v.keepaliveInterval/8, 10*time.Millisecond), 15*time.Second)
	d := base
	for i := 1; i < fails && d < v.keepaliveInterval; i++ {
		d *= 2
	}
	return min(d, v.keepaliveInterval)
}

// deadRetryMultipliers spaces the retries of a DEAD proxy: 1, 3 and 8
// keepalive intervals after each failed attempt. After that it is only
// checked again when a source lists it again.
var deadRetryMultipliers = []time.Duration{1, 3, 8}

func (v *Validator) deadRetryAt(rec *models.Proxy, now time.Time) time.Time {
	k := rec.ConsecutiveFail - v.maxFails
	if k < 0 || k >= len(deadRetryMultipliers) {
		return time.Time{}
	}
	return now.Add(deadRetryMultipliers[k] * v.keepaliveInterval)
}

// calcHealthScore computes a health score between 0 and 1.
//
//	score = latencyScore * 0.4 + successRateScore * 0.6
//
// latencyScore: 1.0 when ≤ 100 ms, linear ramp-down to 0 at ≥ 5000 ms.
// successRateScore: min(consecutiveOK / 10.0, 1.0)
func (v *Validator) calcHealthScore(p *models.Proxy) float64 {
	var latencyScore float64
	switch {
	case p.LatencyMs <= 100:
		latencyScore = 1.0
	case p.LatencyMs >= 5000:
		latencyScore = 0.0
	default:
		latencyScore = 1.0 - float64(p.LatencyMs-100)/4900.0
	}

	successScore := float64(p.ConsecutiveOK) / 10.0
	if successScore > 1.0 {
		successScore = 1.0
	}

	return latencyScore*0.4 + successScore*0.6
}

// DetailedStats returns validator statistics. AvgLatencyMs is the mean of
// successful checks only.
func (v *Validator) DetailedStats() models.ValidatorStats {
	checked := v.checked.Load()
	success := v.successCount.Load()

	var avgLat, rate float64
	if success > 0 {
		avgLat = float64(v.successLatencyMs.Load()) / float64(success)
	}
	if checked > 0 {
		rate = float64(success) / float64(checked) * 100
	}

	reasons := make(map[string]int64)
	for r, c := range v.reasons {
		if n := c.Load(); n > 0 {
			reasons[string(r)] = n
		}
	}

	depth := len(v.queue)
	if v.keepaliveQueue != nil {
		depth += len(v.keepaliveQueue)
	}

	return models.ValidatorStats{
		Workers:              v.workers + v.keepaliveWorkers,
		TotalChecks:          checked,
		SuccessCount:         success,
		FailureCount:         v.failureCount.Load(),
		SuccessRate:          rate,
		AvgLatencyMs:         avgLat,
		Indeterminate:        v.indeterminate.Load(),
		InFlight:             v.inFlightN.Load(),
		QueueDepth:           depth,
		FailureReasons:       reasons,
		RoutingBaselineKnown: v.checker.Baseline().Known(),
	}
}

// FailureCounts returns the failure count per reason (for metrics).
func (v *Validator) FailureCounts() map[Reason]int64 {
	out := make(map[Reason]int64, len(v.reasons))
	for r, c := range v.reasons {
		out[r] = c.Load()
	}
	return out
}
