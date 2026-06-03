package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tatlilimon/proxier/internal/config"
	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/scanner"
	"github.com/tatlilimon/proxier/internal/server"
	"github.com/tatlilimon/proxier/internal/storage"
	"github.com/tatlilimon/proxier/internal/validator"
)

func main() {
	setupLogging()

	cfg, err := config.Load("config.yaml")
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("proxier starting",
		"port", cfg.Server.Port,
		"interval_sec", cfg.Scanner.IntervalSec,
		"workers", cfg.Validator.Workers,
		"version", server.Version,
	)

	p := pool.NewPool()

	store, err := storage.New(cfg.Storage.Backend, cfg.Storage.Path)
	if err != nil {
		slog.Error("failed to open storage", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	proxies, err := store.LoadAll()
	if err != nil {
		slog.Warn("failed to load persisted proxies", "error", err)
	}
	for _, proxy := range proxies {
		p.Add(proxy)
	}
	slog.Info("loaded proxies from storage", "count", len(proxies))

	interval := time.Duration(cfg.Scanner.IntervalSec) * time.Second
	scan := scanner.NewScanner(cfg.Scanner.Sources, interval)

	v := validator.NewValidator(cfg.Validator, p)
	srv := server.NewServer(cfg.Server, p, v, scan, cfg.Validator.ProbeURL)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	proxyCh := make(chan *models.Proxy, cfg.Server.ChannelBufferSize)
	slog.Info("proxy channel created", "buffer_size", cfg.Server.ChannelBufferSize)

	// Scanner mode selection
	switch cfg.Scanner.Mode {
	case "continuous":
		slog.Info("starting scanner in continuous mode", "delay_sec", cfg.Scanner.ContinuousDelaySec)
		go scan.RunContinuous(ctx, proxyCh, cfg.Scanner.ContinuousDelaySec)
	case "interval":
		slog.Info("starting scanner in interval mode", "interval_sec", cfg.Scanner.IntervalSec)
		go scan.Run(ctx, proxyCh)
	default:
		slog.Warn("unknown scanner mode, falling back to interval", "mode", cfg.Scanner.Mode)
		go scan.Run(ctx, proxyCh)
	}

	// Keepalive selection
	if cfg.Validator.KeepaliveWorkers > 0 || cfg.Validator.KeepaliveUseMainChannel {
		slog.Info("starting keepalive workers",
			"workers", cfg.Validator.KeepaliveWorkers,
			"use_main_channel", cfg.Validator.KeepaliveUseMainChannel,
		)
		go v.StartKeepaliveWorkers(ctx, cfg.Validator.KeepaliveWorkers, cfg.Validator.KeepaliveUseMainChannel, proxyCh)
	} else {
		slog.Info("starting sequential keepalive")
		go v.StartKeepalive(ctx)
	}

	// Validator always runs
	go func() { v.Run(ctx, proxyCh) }()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				persistPool(store, p)
			}
		}
	}()

	go func() {
		if err := srv.Start(); err != nil {
			slog.Error("server error", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	persistPool(store, p)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}

	slog.Info("proxier stopped")
}

func persistPool(store storage.Store, p *pool.Pool) {
	proxies := p.DirtyAll()
	for _, proxy := range proxies {
		if err := store.Save(proxy); err != nil {
			slog.Warn("failed to persist proxy", "address", proxy.Address(), "error", err)
		}
	}
}

func setupLogging() {
	level := slog.LevelInfo
	if lv := os.Getenv("LOG_LEVEL"); lv != "" {
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
