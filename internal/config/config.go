package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tatlilimon/proxier/internal/models"
	"gopkg.in/yaml.v3"
)

// Load reads configuration from a YAML file at the given path, applies
// environment variable overrides, and returns a populated *models.Config.
// If the config file does not exist, defaults are returned with env var
// overrides still applied.
func Load(path string) (*models.Config, error) {
	cfg := models.DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnvOverrides(&cfg)
			return &cfg, nil
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	applyEnvOverrides(&cfg)
	return &cfg, nil
}

func applyEnvOverrides(cfg *models.Config) {
	if v := os.Getenv("HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = n
		}
	}
	if v := os.Getenv("SCANNER_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Scanner.IntervalSec = n
		}
	}
	if v := os.Getenv("VALIDATOR_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Validator.Workers = n
		}
	}
	if v := os.Getenv("VALIDATOR_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Validator.TimeoutMs = n
		}
	}
	if v := os.Getenv("VALIDATOR_PROBE_URL"); v != "" {
		cfg.Validator.ProbeURL = v
	}
	if v := os.Getenv("KEEPALIVE_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Validator.KeepaliveIntervalSec = n
		}
	}
	if v := os.Getenv("MAX_CONSECUTIVE_FAILS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Validator.MaxConsecutiveFails = n
		}
	}
	if v := os.Getenv("SCANNER_MODE"); v != "" {
		cfg.Scanner.Mode = v
	}
	if v := os.Getenv("SCANNER_CONTINUOUS_DELAY_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Scanner.ContinuousDelaySec = n
		}
	}
	if v := os.Getenv("CHANNEL_BUFFER_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.ChannelBufferSize = n
		}
	}
	if v := os.Getenv("KEEPALIVE_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Validator.KeepaliveWorkers = n
		}
	}
	if v := os.Getenv("KEEPALIVE_USE_MAIN_CHANNEL"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Validator.KeepaliveUseMainChannel = b
		}
	}
	if v := os.Getenv("STORAGE_BACKEND"); v != "" {
		cfg.Storage.Backend = v
	}
	if v := os.Getenv("STORAGE_PATH"); v != "" {
		cfg.Storage.Path = v
	}
	if v := os.Getenv("REDIS_URL"); v != "" {
		cfg.Storage.RedisURL = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("PROXY_SOURCES"); v != "" {
		for _, url := range strings.Split(v, ",") {
			url = strings.TrimSpace(url)
			if url == "" {
				continue
			}
			cfg.Scanner.Sources = append(cfg.Scanner.Sources, models.SourceConfig{
				URL:      url,
				Format:   models.FormatTXT,
				Protocol: models.ProtoHTTP,
			})
		}
	}
}
