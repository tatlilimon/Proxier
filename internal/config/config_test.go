package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tatlilimon/proxier/internal/models"
	"gopkg.in/yaml.v3"
)

func lookupFrom(env map[string]string) lookupFunc {
	return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
}

func TestShippedConfigIsValid(t *testing.T) {
	cfg := models.DefaultConfig()
	data, err := os.ReadFile("../../config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("config.yaml does not validate: %v", err)
	}
}

func TestMalformedEnvironmentIsAnError(t *testing.T) {
	cfg := models.DefaultConfig()
	err := applyEnvOverrides(&cfg, lookupFrom(map[string]string{"PORT": "80a", "KEEPALIVE_USE_MAIN_CHANNEL": "maybe"}))
	if err == nil || !strings.Contains(err.Error(), "PORT") || !strings.Contains(err.Error(), "KEEPALIVE_USE_MAIN_CHANNEL") {
		t.Fatalf("err = %v, want errors naming PORT and KEEPALIVE_USE_MAIN_CHANNEL", err)
	}
}

func TestEnvironmentOverrides(t *testing.T) {
	cfg := models.DefaultConfig()
	err := applyEnvOverrides(&cfg, lookupFrom(map[string]string{
		"PORT": "9090", "VALIDATOR_WORKERS": "7", "ALLOW_PRIVATE_PROXIES": "true",
		"DEAD_RETENTION_HOURS": "6", "LOG_LEVEL": "debug",
		"PROXY_SOURCES": "https://a.example/l.txt, ,https://b.example/l.txt",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Port != 9090 || cfg.Validator.Workers != 7 || !cfg.Validator.AllowPrivateProxies ||
		cfg.Storage.DeadRetentionHours != 6 || cfg.LogLevel != "debug" || len(cfg.Scanner.Sources) != 2 {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
}

// Audit finding 13: invalid values fail startup with a clear message
// instead of panicking later.
func TestValidateRejectsInvalidValues(t *testing.T) {
	cases := map[string]func(*models.Config){
		"negative channel":   func(c *models.Config) { c.Server.ChannelBufferSize = -1 },
		"zero interval":      func(c *models.Config) { c.Scanner.IntervalSec = 0 },
		"zero keepalive":     func(c *models.Config) { c.Validator.KeepaliveIntervalSec = 0 },
		"zero workers":       func(c *models.Config) { c.Validator.Workers = 0 },
		"tiny timeout":       func(c *models.Config) { c.Validator.TimeoutMs = 5 },
		"zero fails":         func(c *models.Config) { c.Validator.MaxConsecutiveFails = 0 },
		"bad port":           func(c *models.Config) { c.Server.Port = 70000 },
		"bad mode":           func(c *models.Config) { c.Scanner.Mode = "fast" },
		"json backend":       func(c *models.Config) { c.Storage.Backend = "json" },
		"ftp probe":          func(c *models.Config) { c.Validator.ProbeURL = "ftp://x/ip" },
		"probe without host": func(c *models.Config) { c.Validator.ProbeURL = "https:///ip" },
		"bad source url": func(c *models.Config) {
			c.Scanner.Sources = []models.SourceConfig{{URL: "file:///etc/passwd", Protocol: "http"}}
		},
		"bad source format": func(c *models.Config) {
			c.Scanner.Sources = []models.SourceConfig{{URL: "https://a/x", Format: "csv", Protocol: "http"}}
		},
		"bad source proto": func(c *models.Config) {
			c.Scanner.Sources = []models.SourceConfig{{URL: "https://a/x", Protocol: "ftp"}}
		},
		"bad log level":      func(c *models.Config) { c.LogLevel = "loud" },
		"negative dedup":     func(c *models.Config) { c.Scanner.DedupTTLSec = -1 },
		"missing CA file":    func(c *models.Config) { c.Validator.ExtraCAFile = "/nonexistent/ca.pem" },
		"empty storage path": func(c *models.Config) { c.Storage.Path = " " },
	}
	for name, mutate := range cases {
		cfg := models.DefaultConfig()
		mutate(&cfg)
		if err := Validate(&cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cfg := models.DefaultConfig()
	if err := Validate(&cfg); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
}

func TestValidateFillsSourceFormat(t *testing.T) {
	cfg := models.DefaultConfig()
	cfg.Scanner.Sources = []models.SourceConfig{{URL: "https://a.example/x", Protocol: models.ProtoMixed}}
	if err := Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Scanner.Sources[0].Format != models.FormatTXT {
		t.Fatalf("format = %q, want txt", cfg.Scanner.Sources[0].Format)
	}
}

func TestLoadUsesYAMLLogLevelAndReportsBadFiles(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	os.WriteFile(good, []byte("log_level: debug\nvalidator:\n  workers: 3\n"), 0o600)
	t.Setenv("LOG_LEVEL", "")
	cfg, err := Load(good)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" || cfg.Validator.Workers != 3 {
		t.Fatalf("yaml not applied: level %q workers %d", cfg.LogLevel, cfg.Validator.Workers)
	}

	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("validator:\n  workers: 0\n"), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("invalid file accepted")
	}
}
