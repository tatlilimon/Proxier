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
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
	// ChannelBufferSize is the capacity of the check queue between the
	// scheduler and the validator workers.
	ChannelBufferSize int `yaml:"channel_buffer_size" json:"channel_buffer_size"`
}

// ScannerConfig holds proxy scanner configuration.
type ScannerConfig struct {
	IntervalSec        int            `yaml:"interval_sec" json:"interval_sec"`
	Sources            []SourceConfig `yaml:"sources" json:"sources"`
	Mode               string         `yaml:"mode" json:"mode"`
	ContinuousDelaySec int            `yaml:"continuous_delay_sec" json:"continuous_delay_sec"`
	DedupTTLSec        int            `yaml:"dedup_ttl_sec" json:"dedup_ttl_sec"`
}

// ValidatorConfig holds proxy validator configuration.
type ValidatorConfig struct {
	Workers                 int    `yaml:"workers" json:"workers"`
	TimeoutMs               int    `yaml:"timeout_ms" json:"timeout_ms"`
	ProbeURL                string `yaml:"probe_url" json:"probe_url"`
	KeepaliveIntervalSec    int    `yaml:"keepalive_interval_sec" json:"keepalive_interval_sec"`
	MaxConsecutiveFails     int    `yaml:"max_consecutive_fails" json:"max_consecutive_fails"`
	KeepaliveWorkers        int    `yaml:"keepalive_workers" json:"keepalive_workers"`
	KeepaliveUseMainChannel bool   `yaml:"keepalive_use_main_channel" json:"keepalive_use_main_channel"`

	// AllowPrivateProxies permits proxies on loopback, private, link-local
	// and other non-public addresses. Off by default.
	AllowPrivateProxies bool `yaml:"allow_private_proxies" json:"allow_private_proxies"`
	// ExtraCAFile names a PEM file with additional trusted roots for TLS
	// verification (probe and HTTPS proxies). Empty means system roots only.
	ExtraCAFile string `yaml:"extra_ca_file" json:"extra_ca_file"`
}

// StorageConfig holds storage backend configuration.
type StorageConfig struct {
	Backend string `yaml:"backend" json:"backend"` // only "sqlite" is implemented
	Path    string `yaml:"path" json:"path"`
	// DeadRetentionHours removes DEAD records this long after they died.
	// 0 keeps them forever.
	DeadRetentionHours int `yaml:"dead_retention_hours" json:"dead_retention_hours"`
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
	Storage   StorageStats   `json:"storage"`
	Uptime    string         `json:"uptime"`
	Version   string         `json:"version"`
}

// PoolStats holds pool-level statistics.
type PoolStats struct {
	Total int `json:"total"`
	Alive int `json:"alive"`
	// Validating counts records out of rotation that wait for another check.
	Validating int `json:"validating"`
	Dead       int `json:"dead"`
	// Discovered counts candidates waiting for their first check.
	Discovered     int            `json:"discovered"`
	DeadLastHour   int            `json:"dead_last_hour"`
	AvgHealthScore float64        `json:"avg_health_score"`
	Protocols      map[string]int `json:"protocols"`
}

// SourceStatus is the outcome of the most recent fetch of one source.
type SourceStatus struct {
	URL         string    `json:"url"`
	Protocol    Protocol  `json:"protocol"`
	OK          bool      `json:"ok"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastCount   int       `json:"last_count"`
	LastError   string    `json:"last_error,omitempty"`
}

// ScannerStats holds scanner statistics.
type ScannerStats struct {
	LastRun time.Time `json:"last_run"`
	NextRun time.Time `json:"next_run"`
	// SourcesCount is the number of configured sources; SourcesOK the number
	// whose last fetch succeeded.
	SourcesCount int `json:"sources_count"`
	SourcesOK    int `json:"sources_ok"`
	// LastFetchCount is the number of candidates parsed in the last cycle
	// (before deduplication); LastNewCount the records it added to the pool.
	LastFetchCount int `json:"last_fetch_count"`
	LastNewCount   int `json:"last_new_count"`
	// TotalDiscovered counts records added to the pool (unique proxies).
	TotalDiscovered int64 `json:"total_discovered"`
	LastDurationMs  int64 `json:"last_duration_ms"`
	// Dropped is kept for compatibility: candidates are no longer dropped.
	Dropped int64 `json:"dropped"`
	// Rejected counts candidates refused by the address policy.
	Rejected int64          `json:"rejected"`
	Sources  []SourceStatus `json:"sources,omitempty"`
}

// ValidatorStats holds validator statistics.
type ValidatorStats struct {
	Workers      int     `json:"workers"`
	TotalChecks  int64   `json:"total_checks"`
	SuccessCount int64   `json:"success_count"`
	FailureCount int64   `json:"failure_count"`
	SuccessRate  float64 `json:"success_rate_pct"`
	// AvgLatencyMs is the mean latency of successful checks.
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	// Indeterminate counts checks that could not be judged (routing baseline
	// unknown); they count neither as success nor failure.
	Indeterminate        int64            `json:"indeterminate_count"`
	InFlight             int64            `json:"in_flight"`
	QueueDepth           int              `json:"queue_depth"`
	FailureReasons       map[string]int64 `json:"failure_reasons,omitempty"`
	RoutingBaselineKnown bool             `json:"routing_baseline_known"`
}

// StorageStats describes persistence health.
type StorageStats struct {
	Pending     int       `json:"pending"`
	Failures    int64     `json:"failures"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}

// ValidateRequest is the request body for POST /validate.
type ValidateRequest struct {
	Proxy string `json:"proxy"`
}

// ValidateResponse is the response for POST /validate.
type ValidateResponse struct {
	Proxy     string `json:"proxy"`
	Alive     bool   `json:"alive"`
	LatencyMs int    `json:"latency_ms"`
	// Reason explains a negative or indeterminate result.
	Reason string `json:"reason,omitempty"`
}

// ReadyResponse is the response for GET /ready.
type ReadyResponse struct {
	Ready   bool     `json:"ready"`
	Reasons []string `json:"reasons,omitempty"`
}

// ErrorResponse is the standard error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// DefaultConfig returns a Config with the built-in defaults. config.yaml and
// environment variables override them (see README, "Configuration").
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
			ProbeURL:                "https://httpbin.org/ip",
			KeepaliveIntervalSec:    300,
			MaxConsecutiveFails:     5,
			KeepaliveWorkers:        0,
			KeepaliveUseMainChannel: false,
		},
		Storage: StorageConfig{
			Backend:            "sqlite",
			Path:               "./proxies.db",
			DeadRetentionHours: 24,
		},
		LogLevel: "info",
	}
}
