// Package server is proxier's REST API.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
	"github.com/tatlilimon/proxier/internal/netpolicy"
	"github.com/tatlilimon/proxier/internal/pool"
	"github.com/tatlilimon/proxier/internal/scanner"
	"github.com/tatlilimon/proxier/internal/validator"
)

// Version is set at build time via -ldflags. Defaults to "dev" for local
// builds and is overridden to the git tag in Docker builds.
var Version = "dev"

const (
	// maxValidateBody bounds the POST /validate request body.
	maxValidateBody = 4 << 10
	// maxConcurrentValidations bounds on-demand checks running at once.
	maxConcurrentValidations = 8
)

// StorageStats reports persistence health for /stats.
type StorageStats interface {
	Stats() models.StorageStats
}

// Deps are the components the API reads.
type Deps struct {
	Pool      *pool.Pool
	Validator *validator.Validator
	Scanner   *scanner.Scanner
	Storage   StorageStats
	Metrics   http.Handler
	// AllowPrivate admits private proxy addresses in POST /validate.
	AllowPrivate bool
}

// Server serves the REST API.
type Server struct {
	httpServer   *http.Server
	pool         *pool.Pool
	validator    *validator.Validator
	scanner      *scanner.Scanner
	storage      StorageStats
	allowPrivate bool
	startTime    time.Time
	validateSem  chan struct{}
}

// NewServer builds the API for cfg and deps.
func NewServer(cfg models.ServerConfig, deps Deps) *Server {
	srv := &Server{
		pool:         deps.Pool,
		validator:    deps.Validator,
		scanner:      deps.Scanner,
		storage:      deps.Storage,
		allowPrivate: deps.AllowPrivate,
		startTime:    time.Now(),
		validateSem:  make(chan struct{}, maxConcurrentValidations),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxy", srv.handleGetProxy)
	mux.HandleFunc("GET /proxies", srv.handleGetProxies)
	mux.HandleFunc("GET /rotate", srv.handleRotate)
	mux.HandleFunc("GET /stats", srv.handleStats)
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("GET /ready", srv.handleReady)
	mux.HandleFunc("POST /validate", srv.handleValidate)
	if deps.Metrics != nil {
		mux.Handle("GET /metrics", deps.Metrics)
	}

	writeTimeout := 30 * time.Second
	if deps.Validator != nil {
		writeTimeout = max(writeTimeout, deps.Validator.Checker().Timeout()+10*time.Second)
	}
	srv.httpServer = &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           srv.loggingMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	return srv
}

// Addr is the configured listen address.
func (s *Server) Addr() string { return s.httpServer.Addr }

// Listen binds the configured address, so a port conflict fails startup
// before any worker starts.
func (s *Server) Listen() (net.Listener, error) {
	l, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return nil, fmt.Errorf("server listen on %s: %w", s.httpServer.Addr, err)
	}
	return l, nil
}

// Serve serves on l until Shutdown. It returns nil after a clean shutdown.
func (s *Server) Serve(l net.Listener) error {
	slog.Info("server starting", "addr", l.Addr().String())
	if err := s.httpServer.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("server shutting down")
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the HTTP handler (for tests).
func (s *Server) Handler() http.Handler { return s.httpServer.Handler }

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
	proxy, err := s.pool.GetRandom(parseFilterFromQuery(r))
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
		limit = min(l, 100)
	}

	proxies := s.pool.GetN(limit, q.Get("sort"), parseFilterFromQuery(r))
	resp := make([]models.ProxyResponse, 0, len(proxies))
	for _, p := range proxies {
		resp = append(resp, proxyToResponse(p, q.Get("format")))
	}
	writeJSON(w, http.StatusOK, models.ProxiesResponse{Count: len(resp), Proxies: resp})
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	proxy, err := s.pool.GetRoundRobin(parseFilterFromQuery(r))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "no proxy available: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proxyToResponse(proxy, r.URL.Query().Get("format")))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	resp := models.StatsResponse{
		Pool:      s.pool.DetailedStats(),
		Scanner:   s.scanner.DetailedStats(),
		Validator: s.validator.DetailedStats(),
		Uptime:    (time.Duration(time.Since(s.startTime).Seconds()) * time.Second).String(),
		Version:   Version,
	}
	if s.storage != nil {
		resp.Storage = s.storage.Stats()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHealth is a liveness probe: 200 even with an empty pool.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady is a readiness probe: 200 only when proxies can be served.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	var reasons []string
	if s.pool.Size() == 0 {
		reasons = append(reasons, "no alive proxies")
	}
	if !s.validator.Checker().Baseline().Known() {
		reasons = append(reasons, "routing baseline unknown (leak detection unavailable)")
	}
	if s.scanner.DetailedStats().LastRun.IsZero() && s.pool.Len() == 0 {
		reasons = append(reasons, "first scan not finished")
	}
	status := http.StatusOK
	if len(reasons) > 0 {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, models.ReadyResponse{Ready: len(reasons) == 0, Reasons: reasons})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxValidateBody)
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
	if err := netpolicy.CheckHost(host, s.allowPrivate); err != nil {
		writeError(w, http.StatusBadRequest, err.Error()+"; set validator.allow_private_proxies to permit it")
		return
	}

	select {
	case s.validateSem <- struct{}{}:
		defer func() { <-s.validateSem }()
	default:
		writeError(w, http.StatusTooManyRequests, "too many validations in progress, retry later")
		return
	}

	p := models.NewCandidate(protocol, host, port, "api", time.Now())
	res := s.validator.Checker().Check(r.Context(), p)
	writeJSON(w, http.StatusOK, models.ValidateResponse{
		Proxy:     req.Proxy,
		Alive:     res.OK,
		LatencyMs: int(res.Latency.Milliseconds()),
		Reason:    string(res.Reason),
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
	return pool.PoolFilter{Protocol: protocol, MaxLatencyMs: maxLatencyMs}
}

func proxyToResponse(p *models.Proxy, format string) models.ProxyResponse {
	addr := p.URL()
	if format == "hostport" {
		addr = p.Address()
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

// parseProxyString accepts "host:port" (HTTP) or "scheme://host:port" with a
// supported scheme. IPv6 hosts must be bracketed. The port must be 1-65535.
func parseProxyString(raw string) (host string, port int, protocol models.Protocol, err error) {
	raw = strings.TrimSpace(raw)
	var portStr string

	if strings.Contains(raw, "://") {
		u, perr := url.Parse(raw)
		if perr != nil {
			return "", 0, "", fmt.Errorf("invalid URL: %w", perr)
		}
		p, ok := models.ParseScheme(u.Scheme)
		if !ok {
			return "", 0, "", fmt.Errorf("unsupported scheme %q (use http, https, socks4 or socks5)", u.Scheme)
		}
		if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return "", 0, "", errors.New("only scheme://host:port is accepted")
		}
		protocol, host, portStr = p, u.Hostname(), u.Port()
		if portStr == "" {
			return "", 0, "", errors.New("port is required")
		}
	} else {
		h, ps, serr := net.SplitHostPort(raw)
		if serr != nil {
			return "", 0, "", fmt.Errorf("expected host:port or protocol://host:port: %w", serr)
		}
		protocol, host, portStr = models.ProtoHTTP, h, ps
	}

	if host == "" {
		return "", 0, "", errors.New("host is required")
	}
	if len(host) > 253 || strings.ContainsAny(host, " \t/@") {
		return "", 0, "", fmt.Errorf("invalid host %q", host)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", fmt.Errorf("invalid port %q (must be 1-65535)", portStr)
	}
	return models.NormalizeHost(host), port, protocol, nil
}
