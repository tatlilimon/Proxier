package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tatlilimon/proxier/internal/metrics"
	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/scanner"
	"github.com/tatlilimon/proxier/internal/validator"
)

// Version is set at build time via -ldflags. Defaults to "dev" for local
// builds and is overridden to the git tag in Docker builds.
var Version = "dev"

type Server struct {
	httpServer *http.Server
	pool       *pool.Pool
	validator  *validator.Validator
	scanner    *scanner.Scanner
	startTime  time.Time
	probeURL   string
}

func NewServer(
	cfg models.ServerConfig,
	p *pool.Pool,
	v *validator.Validator,
	s *scanner.Scanner,
	probeURL string,
) *Server {
	srv := &Server{
		pool:      p,
		validator: v,
		scanner:   s,
		startTime: time.Now(),
		probeURL:  probeURL,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxy", srv.handleGetProxy)
	mux.HandleFunc("GET /proxies", srv.handleGetProxies)
	mux.HandleFunc("GET /rotate", srv.handleRotate)
	mux.HandleFunc("GET /stats", srv.handleStats)
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("POST /validate", srv.handleValidate)
	mux.HandleFunc("GET /metrics", metrics.New(p, s, v, srv.startTime).Handler())

	srv.httpServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler: srv.loggingMiddleware(mux),
	}

	return srv
}

func (s *Server) Start() error {
	slog.Info("server starting", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server listen: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("server shutting down")
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) WaitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration", time.Since(start).String(),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (s *Server) handleGetProxy(w http.ResponseWriter, r *http.Request) {
	filter := parseFilterFromQuery(r)
	proxy, err := s.pool.GetRandom(filter)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "no proxy available: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proxyToResponse(proxy, r.URL.Query().Get("format")))
}

func (s *Server) handleGetProxies(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := 10
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
		if limit > 100 {
			limit = 100
		}
	}

	sortBy := q.Get("sort")
	format := q.Get("format")
	filter := parseFilterFromQuery(r)

	proxies := s.pool.GetN(limit, sortBy, filter)
	resp := make([]models.ProxyResponse, 0, len(proxies))
	for _, p := range proxies {
		resp = append(resp, proxyToResponse(p, format))
	}

	writeJSON(w, http.StatusOK, models.ProxiesResponse{
		Count:   len(resp),
		Proxies: resp,
	})
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	filter := parseFilterFromQuery(r)
	proxy, err := s.pool.GetRoundRobin(filter)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "no proxy available: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proxyToResponse(proxy, r.URL.Query().Get("format")))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	poolStats := s.pool.DetailedStats()

	scannerStats := s.scanner.DetailedStats()
	validatorStats := s.validator.DetailedStats()

	uptimeSec := int64(time.Since(s.startTime).Seconds())

	resp := models.StatsResponse{
		Pool:      poolStats,
		Scanner:   scannerStats,
		Validator: validatorStats,
		Uptime:    (time.Duration(uptimeSec) * time.Second).String(),
		Version:   Version,
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req models.ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.Proxy == "" {
		writeError(w, http.StatusBadRequest, "proxy field is required")
		return
	}

	host, port, protocol, err := parseProxyString(req.Proxy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid proxy format: "+err.Error())
		return
	}

	p := &models.Proxy{
		Host:     host,
		Port:     port,
		Protocol: protocol,
	}

	alive, latencyMs := validateProxy(r.Context(), p, s.probeURL)

	writeJSON(w, http.StatusOK, models.ValidateResponse{
		Proxy:     req.Proxy,
		Alive:     alive,
		LatencyMs: latencyMs,
	})
}

func parseFilterFromQuery(r *http.Request) pool.PoolFilter {
	q := r.URL.Query()

	protocol := q.Get("protocol")
	if protocol == "any" {
		protocol = ""
	}

	maxLatencyMs := 0
	if v, err := strconv.Atoi(q.Get("max_latency_ms")); err == nil {
		maxLatencyMs = v
	}

	return pool.PoolFilter{
		Protocol:     protocol,
		MaxLatencyMs: maxLatencyMs,
	}
}

func proxyToResponse(p *models.Proxy, format string) models.ProxyResponse {
	var addr string
	switch format {
	case "hostport":
		addr = p.Address()
	default:
		addr = p.URL()
	}
	return models.ProxyResponse{
		Proxy:       addr,
		Protocol:    p.Protocol,
		LatencyMs:   p.LatencyMs,
		HealthScore: p.HealthScore,
		Country:     p.Country,
		LastChecked: p.LastChecked,
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, models.ErrorResponse{Error: msg})
}

func parseProxyString(raw string) (host string, port int, protocol models.Protocol, err error) {
	raw = strings.TrimSpace(raw)

	if strings.Contains(raw, "://") {
		u, parseErr := url.Parse(raw)
		if parseErr != nil {
			err = fmt.Errorf("invalid URL: %w", parseErr)
			return
		}
		host = u.Hostname()
		portStr := u.Port()
		if portStr == "" {
			err = fmt.Errorf("port is required")
			return
		}
		port, err = strconv.Atoi(portStr)
		if err != nil {
			err = fmt.Errorf("invalid port: %s", portStr)
			return
		}
		protocol = models.Protocol(u.Scheme)
		return
	}

	h, pStr, splitErr := net.SplitHostPort(raw)
	if splitErr != nil {
		err = fmt.Errorf("expected host:port or protocol://host:port: %w", splitErr)
		return
	}
	host = h
	port, err = strconv.Atoi(pStr)
	if err != nil {
		err = fmt.Errorf("invalid port: %s", pStr)
		return
	}
	protocol = models.ProtoHTTP
	return
}

func validateProxy(ctx context.Context, p *models.Proxy, probeURL string) (alive bool, latencyMs int) {
	if probeURL == "" {
		probeURL = "http://httpbin.org/ip"
	}

	proxyURL, err := url.Parse(p.URL())
	if err != nil {
		return false, 0
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
		IdleConnTimeout:     90 * time.Second,
		MaxConnsPerHost:     2,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return false, 0
	}

	start := time.Now()
	resp, err := client.Do(req)
	latencyMs = int(time.Since(start).Milliseconds())

	if err != nil {
		return false, latencyMs
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 300, latencyMs
}
