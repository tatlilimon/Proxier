package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/tatlilimon/proxier/internal/config"
	"github.com/tatlilimon/proxier/internal/metrics"
	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/scanner"
	"github.com/tatlilimon/proxier/internal/server"
	"github.com/tatlilimon/proxier/internal/storage"
	"github.com/tatlilimon/proxier/internal/validator"
)

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxier: invalid configuration:\n%v\n", err)
		os.Exit(2)
	}
	setupLogging(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, runOptions{}); err != nil {
		slog.Error("proxier stopped with an error", "error", err)
		os.Exit(1)
	}
	slog.Info("proxier stopped")
}

// runOptions lets tests inject components and shorten timings.
type runOptions struct {
	store         storage.Store
	validatorOpts []validator.Option
	persistEvery  time.Duration
	maintainEvery time.Duration
	// ready receives the API address once the listener is bound.
	ready chan<- string
}

// run starts every component and blocks until ctx is cancelled or the API
// fails. Shutdown is ordered: stop the API, stop scanning and checking and
// wait for in-flight work, write the final state, close storage. A listener
// failure or a final write that cannot be completed is returned as an error.
func run(ctx context.Context, cfg *models.Config, opts runOptions) (runErr error) {
	slog.Info("proxier starting",
		"port", cfg.Server.Port,
		"scanner_mode", cfg.Scanner.Mode,
		"workers", cfg.Validator.Workers,
		"version", server.Version,
	)

	store := opts.store
	if store == nil {
		var err error
		if store, err = storage.New(cfg.Storage.Backend, cfg.Storage.Path); err != nil {
			return fmt.Errorf("opening storage: %w", err)
		}
	}
	defer func() {
		if err := store.Close(); err != nil {
			slog.Error("closing storage", "error", err)
		}
	}()

	keepalive := time.Duration(cfg.Validator.KeepaliveIntervalSec) * time.Second
	p := pool.NewPool()
	records, err := store.LoadAll()
	if err != nil {
		slog.Warn("failed to load persisted proxies; starting empty", "error", err)
	}
	quarantined := p.Load(records, time.Now(), keepalive)
	slog.Info("loaded proxies from storage", "count", len(records), "quarantined_until_rechecked", quarantined)

	m := metrics.New()
	vopts := append([]validator.Option{
		validator.WithLatencyObserver(m.ObserveLatency),
		validator.WithUserAgent("proxier/" + server.Version),
	}, opts.validatorOpts...)
	v, err := validator.NewValidator(cfg.Validator, cfg.Server.ChannelBufferSize, p, vopts...)
	if err != nil {
		return fmt.Errorf("creating validator: %w", err)
	}
	if u := cfg.Validator.ProbeURL; len(u) >= 7 && u[:7] == "http://" {
		slog.Warn("the probe URL uses plain HTTP: a proxy can forge its answer; use https")
	}

	scan := scanner.NewScanner(cfg.Scanner.Sources,
		time.Duration(cfg.Scanner.IntervalSec)*time.Second,
		time.Duration(cfg.Scanner.DedupTTLSec)*time.Second,
		cfg.Validator.AllowPrivateProxies)
	per := &persister{store: store, pool: p}
	m.Register(p, scan, v, per, time.Now())

	srv := server.NewServer(cfg.Server, server.Deps{
		Pool: p, Validator: v, Scanner: scan, Storage: per,
		Metrics: m.Handler(), AllowPrivate: cfg.Validator.AllowPrivateProxies,
	})
	listener, err := srv.Listen()
	if err != nil {
		return err
	}
	if opts.ready != nil {
		opts.ready <- listener.Addr().String()
	}

	persistEvery := opts.persistEvery
	if persistEvery <= 0 {
		persistEvery = 5 * time.Second
	}
	maintainEvery := opts.maintainEvery
	if maintainEvery <= 0 {
		maintainEvery = min(keepalive, time.Minute)
	}

	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()

	var workers sync.WaitGroup
	workers.Go(func() { v.Run(workCtx) })
	workers.Go(func() {
		if cfg.Scanner.Mode == "continuous" {
			scan.RunContinuous(workCtx, p, cfg.Scanner.ContinuousDelaySec)
		} else {
			scan.Run(workCtx, p)
		}
	})
	workers.Go(func() {
		maintain(workCtx, p, maintainEvery, 3*keepalive, time.Duration(cfg.Storage.DeadRetentionHours)*time.Hour)
	})
	persistDone := make(chan struct{})
	go func() {
		per.loop(workCtx, persistEvery)
		close(persistDone)
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(listener) }()

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err := <-serveErr:
		if err == nil {
			err = errors.New("API server stopped unexpectedly")
		}
		runErr = err
		slog.Error("API server failed; shutting down", "error", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown", "error", err)
	}

	cancelWork()
	workers.Wait()
	<-persistDone

	if err := per.flushWithRetry(3); err != nil {
		slog.Error("final persistence failed", "error", err)
		if runErr == nil {
			runErr = fmt.Errorf("final persistence: %w", err)
		}
	}
	return runErr
}

// maintain periodically takes stale ALIVE records out of rotation and
// removes DEAD records past their retention.
func maintain(ctx context.Context, p *pool.Pool, every, staleAfter, deadRetention time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			if n := p.DemoteStale(now, staleAfter); n > 0 {
				slog.Warn("demoted stale proxies until they are rechecked", "count", n, "stale_after", staleAfter.String())
			}
			if n := p.Prune(now, deadRetention); n > 0 {
				slog.Info("removed dead proxies past retention", "count", n)
			}
		}
	}
}

// persister writes pool changes to storage. A change is marked clean only
// after the write that contained it succeeded.
type persister struct {
	store storage.Store
	pool  *pool.Pool

	mu          sync.Mutex
	failures    int64
	lastSuccess time.Time
	lastErr     string
}

func (s *persister) flush() error {
	upserts, deletes, ack := s.pool.DirtySnapshot()
	if len(upserts) == 0 && len(deletes) == 0 {
		return nil
	}
	if err := s.store.Apply(upserts, deletes); err != nil {
		s.mu.Lock()
		s.failures++
		s.lastErr = err.Error()
		s.mu.Unlock()
		return err
	}
	s.pool.Acknowledge(ack)
	s.mu.Lock()
	s.lastSuccess = time.Now()
	s.lastErr = ""
	s.mu.Unlock()
	return nil
}

func (s *persister) loop(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.flush(); err != nil {
				slog.Warn("failed to persist proxies; will retry", "pending", s.pool.Pending(), "error", err)
			}
		}
	}
}

func (s *persister) flushWithRetry(attempts int) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = s.flush(); err == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}
	return err
}

// Stats implements metrics.StorageStats and server.StorageStats.
func (s *persister) Stats() models.StorageStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return models.StorageStats{
		Pending:     s.pool.Pending(),
		Failures:    s.failures,
		LastSuccess: s.lastSuccess,
		LastError:   s.lastErr,
	}
}

func setupLogging(levelName string) {
	level := slog.LevelInfo
	if lv, ok := config.ParseLevel(levelName); ok {
		switch lv {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
