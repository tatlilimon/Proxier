package main

import (
	"context"
	"log"
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
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	log.Printf("proxier starting (port=%d, interval=%ds, workers=%d)",
		cfg.Server.Port, cfg.Scanner.IntervalSec, cfg.Validator.Workers)

	p := pool.NewPool()

	store, err := storage.New(cfg.Storage.Backend, cfg.Storage.Path)
	if err != nil {
		log.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	proxies, err := store.LoadAll()
	if err != nil {
		log.Printf("warning: failed to load persisted proxies: %v", err)
	}
	for _, proxy := range proxies {
		p.Add(proxy)
	}
	log.Printf("loaded %d proxies from storage", len(proxies))

	interval := time.Duration(cfg.Scanner.IntervalSec) * time.Second
	scan := scanner.NewScanner(cfg.Scanner.Sources, interval)

	v := validator.NewValidator(cfg.Validator, p)
	srv := server.NewServer(cfg.Server, p, v, scan, cfg.Validator.ProbeURL)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	proxyCh := make(chan *models.Proxy, 2000)

	go func() {
		v.Run(ctx, proxyCh)
	}()

	go func() {
		v.StartKeepalive(ctx)
	}()

	go func() {
		scan.Run(ctx, proxyCh)
	}()

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
			log.Printf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	persistPool(store, p)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}

	log.Println("proxier stopped")
}

func persistPool(store storage.Store, p *pool.Pool) {
	proxies := p.All()
	for _, proxy := range proxies {
		if err := store.Save(proxy); err != nil {
			log.Printf("failed to persist proxy %s: %v", proxy.Address(), err)
		}
	}
}
