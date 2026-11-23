// Package config loads and validates proxier's configuration.
//
// Three layers apply in order, later ones winning: the built-in defaults
// (models.DefaultConfig), the YAML file, and environment variables. The
// merged result is validated once; any invalid value, including a malformed
// environment variable, is a startup error.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/tatlilimon/proxier/internal/models"
	"gopkg.in/yaml.v3"
)

// Load reads the YAML file at path (a missing file means "defaults only"),
// applies environment overrides and validates the result.
func Load(path string) (*models.Config, error) {
	cfg := models.DefaultConfig()

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", path, err)
		}
	case os.IsNotExist(err):
	default:
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if err := applyEnvOverrides(&cfg, os.LookupEnv); err != nil {
		return nil, err
	}
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

type lookupFunc func(string) (string, bool)

// applyEnvOverrides applies every set environment variable. A variable that
// is set but malformed is an error; it never silently falls back.
func applyEnvOverrides(cfg *models.Config, lookup lookupFunc) error {
	var errs []error
	str := func(name string, dst *string) {
		if v, ok := lookup(name); ok && v != "" {
			*dst = v
		}
	}
	num := func(name string, dst *int) {
		v, ok := lookup(name)
		if !ok || v == "" {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s=%q is not an integer", name, v))
			return
		}
		*dst = n
	}
	boolean := func(name string, dst *bool) {
		v, ok := lookup(name)
		if !ok || v == "" {
			return
		}
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s=%q is not a boolean", name, v))
			return
		}
		*dst = b
	}

	str("HOST", &cfg.Server.Host)
	num("PORT", &cfg.Server.Port)
	num("CHANNEL_BUFFER_SIZE", &cfg.Server.ChannelBufferSize)

	num("SCANNER_INTERVAL_SEC", &cfg.Scanner.IntervalSec)
	str("SCANNER_MODE", &cfg.Scanner.Mode)
	num("SCANNER_CONTINUOUS_DELAY_SEC", &cfg.Scanner.ContinuousDelaySec)
	num("SCANNER_DEDUP_TTL_SEC", &cfg.Scanner.DedupTTLSec)

	num("VALIDATOR_WORKERS", &cfg.Validator.Workers)
	num("VALIDATOR_TIMEOUT_MS", &cfg.Validator.TimeoutMs)
	str("VALIDATOR_PROBE_URL", &cfg.Validator.ProbeURL)
	num("KEEPALIVE_INTERVAL_SEC", &cfg.Validator.KeepaliveIntervalSec)
	num("MAX_CONSECUTIVE_FAILS", &cfg.Validator.MaxConsecutiveFails)
	num("KEEPALIVE_WORKERS", &cfg.Validator.KeepaliveWorkers)
	boolean("KEEPALIVE_USE_MAIN_CHANNEL", &cfg.Validator.KeepaliveUseMainChannel)
	boolean("ALLOW_PRIVATE_PROXIES", &cfg.Validator.AllowPrivateProxies)
	str("EXTRA_CA_FILE", &cfg.Validator.ExtraCAFile)

	str("STORAGE_BACKEND", &cfg.Storage.Backend)
	str("STORAGE_PATH", &cfg.Storage.Path)
	num("DEAD_RETENTION_HOURS", &cfg.Storage.DeadRetentionHours)

	str("LOG_LEVEL", &cfg.LogLevel)

	if v, ok := lookup("PROXY_SOURCES"); ok {
		for _, u := range strings.Split(v, ",") {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			cfg.Scanner.Sources = append(cfg.Scanner.Sources, models.SourceConfig{
				URL:      u,
				Format:   models.FormatTXT,
				Protocol: models.ProtoHTTP,
			})
		}
	}
	return errors.Join(errs...)
}

// Validate checks ranges, enumerations and URLs of a merged configuration
// and fills in defaults for empty enumerations (format "txt", backend
// "sqlite"). It reports every problem at once.
func Validate(cfg *models.Config) error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if strings.TrimSpace(cfg.Server.Host) == "" {
		bad("server.host must not be empty")
	}
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		bad("server.port %d must be between 1 and 65535", cfg.Server.Port)
	}
	if cfg.Server.ChannelBufferSize < 1 || cfg.Server.ChannelBufferSize > 1_000_000 {
		bad("server.channel_buffer_size %d must be between 1 and 1000000", cfg.Server.ChannelBufferSize)
	}

	switch cfg.Scanner.Mode {
	case "interval":
		if cfg.Scanner.IntervalSec < 1 {
			bad("scanner.interval_sec %d must be at least 1", cfg.Scanner.IntervalSec)
		}
	case "continuous":
		if cfg.Scanner.ContinuousDelaySec < 0 {
			bad("scanner.continuous_delay_sec %d must not be negative", cfg.Scanner.ContinuousDelaySec)
		}
	default:
		bad("scanner.mode %q must be \"interval\" or \"continuous\"", cfg.Scanner.Mode)
	}
	if cfg.Scanner.DedupTTLSec < 0 {
		bad("scanner.dedup_ttl_sec %d must not be negative", cfg.Scanner.DedupTTLSec)
	}
	for i := range cfg.Scanner.Sources {
		src := &cfg.Scanner.Sources[i]
		if err := checkHTTPURL(src.URL); err != nil {
			bad("scanner.sources[%d].url: %v", i, err)
		}
		if src.Format == "" {
			src.Format = models.FormatTXT
		}
		if src.Format != models.FormatTXT && src.Format != models.FormatJSON {
			bad("scanner.sources[%d].format %q must be \"txt\" or \"json\"", i, src.Format)
		}
		if !src.Protocol.ValidSource() {
			bad("scanner.sources[%d].protocol %q must be http, https, socks4, socks5 or mixed", i, src.Protocol)
		}
	}

	v := cfg.Validator
	if v.Workers < 1 || v.Workers > 10_000 {
		bad("validator.workers %d must be between 1 and 10000", v.Workers)
	}
	if v.TimeoutMs < 100 || v.TimeoutMs > 120_000 {
		bad("validator.timeout_ms %d must be between 100 and 120000", v.TimeoutMs)
	}
	if err := checkHTTPURL(v.ProbeURL); err != nil {
		bad("validator.probe_url: %v", err)
	}
	if v.KeepaliveIntervalSec < 1 {
		bad("validator.keepalive_interval_sec %d must be at least 1", v.KeepaliveIntervalSec)
	}
	if v.MaxConsecutiveFails < 1 {
		bad("validator.max_consecutive_fails %d must be at least 1", v.MaxConsecutiveFails)
	}
	if v.KeepaliveWorkers < 0 || v.KeepaliveWorkers > 10_000 {
		bad("validator.keepalive_workers %d must be between 0 and 10000", v.KeepaliveWorkers)
	}
	if v.ExtraCAFile != "" {
		if _, err := os.Stat(v.ExtraCAFile); err != nil {
			bad("validator.extra_ca_file: %v", err)
		}
	}

	if cfg.Storage.Backend == "" {
		cfg.Storage.Backend = "sqlite"
	}
	if !strings.EqualFold(cfg.Storage.Backend, "sqlite") {
		bad("storage.backend %q is not supported (only \"sqlite\")", cfg.Storage.Backend)
	}
	if strings.TrimSpace(cfg.Storage.Path) == "" {
		bad("storage.path must not be empty")
	}
	if cfg.Storage.DeadRetentionHours < 0 {
		bad("storage.dead_retention_hours %d must not be negative", cfg.Storage.DeadRetentionHours)
	}

	if _, ok := ParseLevel(cfg.LogLevel); !ok {
		bad("log_level %q must be debug, info, warn or error", cfg.LogLevel)
	}
	return errors.Join(errs...)
}

func checkHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q must use http or https", raw)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%q has no host", raw)
	}
	return nil
}

// Level is a log level name accepted by log_level / LOG_LEVEL.
type Level string

// ParseLevel validates a level name; empty means "info".
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return "info", true
	case "debug":
		return "debug", true
	case "warn", "warning":
		return "warn", true
	case "error":
		return "error", true
	}
	return "", false
}
