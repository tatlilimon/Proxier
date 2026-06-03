package models

import "time"

// SourceFormat describes the output format of a proxy source.
type SourceFormat string

const (
	FormatTXT  SourceFormat = "txt"
	FormatJSON SourceFormat = "json"
)

// SourceConfig defines a single proxy source to scrape.
type SourceConfig struct {
	URL      string       `yaml:"url" json:"url"`
	Format   SourceFormat `yaml:"format" json:"format"`
	Protocol Protocol     `yaml:"protocol" json:"protocol"`
}

// Config holds the full application configuration.
type Config struct {
	Server    ServerConfig    `yaml:"server" json:"server"`
	Scanner   ScannerConfig   `yaml:"scanner" json:"scanner"`
	Validator ValidatorConfig `yaml:"validator" json:"validator"`
	Storage   StorageConfig   `yaml:"storage" json:"storage"`
	LogLevel  string          `yaml:"log_level" json:"log_level"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host              string `yaml:"host" json:"host"`
	Port              int    `yaml:"port" json:"port"`
	ChannelBufferSize int    `yaml:"channel_buffer_size" json:"channel_buffer_size"`
}

// ScannerConfig holds proxy scanner configuration.
type ScannerConfig struct {
	IntervalSec int            `yaml:"interval_sec" json:"interval_sec"`
	Sources     []SourceConfig `yaml:"sources" json:"sources"`
	Mode               string `yaml:"mode" json:"mode"`
	ContinuousDelaySec int    `yaml:"continuous_delay_sec" json:"continuous_delay_sec"`
	DedupTTLSec        int    `yaml:"dedup_ttl_sec" json:"dedup_ttl_sec"`
}

// ValidatorConfig holds proxy validator configuration.
type ValidatorConfig struct {
	Workers               int    `yaml:"workers" json:"workers"`
	TimeoutMs             int    `yaml:"timeout_ms" json:"timeout_ms"`
	ProbeURL              string `yaml:"probe_url" json:"probe_url"`
	KeepaliveIntervalSec  int    `yaml:"keepalive_interval_sec" json:"keepalive_interval_sec"`
	MaxConsecutiveFails   int    `yaml:"max_consecutive_fails" json:"max_consecutive_fails"`
	KeepaliveWorkers      int  `yaml:"keepalive_workers" json:"keepalive_workers"`
	KeepaliveUseMainChannel bool `yaml:"keepalive_use_main_channel" json:"keepalive_use_main_channel"`
}

// StorageConfig holds storage backend configuration.
type StorageConfig struct {
	Backend  string `yaml:"backend" json:"backend"`   // "sqlite" or "json"
	Path     string `yaml:"path" json:"path"`
	RedisURL string `yaml:"redis_url" json:"redis_url"`
}

// ProxyResponse is the JSON structure returned by the HTTP API for a single proxy.
type ProxyResponse struct {
	Proxy       string    `json:"proxy"`
	Protocol    Protocol  `json:"protocol"`
	LatencyMs   int       `json:"latency_ms"`
	HealthScore float64   `json:"health_score"`
	Country     string    `json:"country,omitempty"`
	LastChecked time.Time `json:"last_checked"`
}

// ProxiesResponse is the JSON structure returned by GET /proxies.
type ProxiesResponse struct {
	Count   int             `json:"count"`
	Proxies []ProxyResponse `json:"proxies"`
}

// StatsResponse is the JSON structure returned by GET /stats.
type StatsResponse struct {
	Pool      PoolStats      `json:"pool"`
	Scanner   ScannerStats   `json:"scanner"`
	Validator ValidatorStats `json:"validator"`
	Uptime  string         `json:"uptime"`
	Version   string         `json:"version"`
}

// PoolStats holds pool-level statistics.
type PoolStats struct {
	Total          int            `json:"total"`
	Alive          int            `json:"alive"`
	Validating     int            `json:"validating"`
	Dead           int            `json:"dead"`
	DeadLastHour   int            `json:"dead_last_hour"`
	AvgHealthScore float64        `json:"avg_health_score"`
	Protocols      map[string]int `json:"protocols"`
}

// ScannerStats holds scanner statistics.
type ScannerStats struct {
	LastRun         time.Time `json:"last_run"`
	NextRun         time.Time `json:"next_run"`
	SourcesCount    int       `json:"sources_count"`
	LastFetchCount  int       `json:"last_fetch_count"`
	TotalDiscovered int64     `json:"total_discovered"`
	LastDurationMs  int64     `json:"last_duration_ms"`
	Dropped         int64     `json:"dropped"`
}

// ValidatorStats holds validator statistics.
type ValidatorStats struct {
	Workers      int     `json:"workers"`
	TotalChecks  int64   `json:"total_checks"`
	SuccessCount int64   `json:"success_count"`
	FailureCount int64   `json:"failure_count"`
	SuccessRate  float64 `json:"success_rate_pct"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

// ValidateRequest is the request body for POST /validate.
type ValidateRequest struct {
	Proxy string `json:"proxy"`
}

// ValidateResponse is the response for POST /validate.
type ValidateResponse struct {
	Proxy      string `json:"proxy"`
	Alive      bool   `json:"alive"`
	LatencyMs  int    `json:"latency_ms"`
}

// ErrorResponse is the standard error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Server: ServerConfig{
			Host:              "127.0.0.1",
			Port:              8080,
			ChannelBufferSize: 2000,
		},
		Scanner: ScannerConfig{
			IntervalSec:        600,
			Sources:            nil,
			Mode:               "interval",
			ContinuousDelaySec: 30,
			DedupTTLSec:        1800,
		},
		Validator: ValidatorConfig{
			Workers:                 20,
			TimeoutMs:               10000,
			ProbeURL:                "http://httpbin.org/ip",
			KeepaliveIntervalSec:    300,
			MaxConsecutiveFails:     5,
			KeepaliveWorkers:        0,
			KeepaliveUseMainChannel: false,
		},
		Storage: StorageConfig{
			Backend: "sqlite",
			Path:    "./proxies.db",
		},
		LogLevel: "info",
	}
}
