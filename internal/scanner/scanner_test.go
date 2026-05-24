package scanner

import (
	"strings"
	"testing"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
)

func TestParseTXT(t *testing.T) {
	testSrc := models.SourceConfig{
		URL:      "test-source",
		Protocol: models.ProtoHTTP,
	}

	tests := []struct {
		name     string
		body     string
		wantLen  int
		wantHost string
		wantPort int
	}{
		{
			name:     "valid ip:port",
			body:     "1.2.3.4:8080",
			wantLen:  1,
			wantHost: "1.2.3.4",
			wantPort: 8080,
		},
		{
			name:     "valid ip and port with spaces around colon",
			body:     "1.2.3.4 : 8080",
			wantLen:  1,
			wantHost: "1.2.3.4",
			wantPort: 8080,
		},
		{
			name:    "comment line starting with hash",
			body:    "# this is a comment",
			wantLen: 0,
		},
		{
			name:    "empty line",
			body:    "",
			wantLen: 0,
		},
		{
			name:    "line without colon",
			body:    "just some text",
			wantLen: 0,
		},
		{
			name:    "port too high",
			body:    "1.2.3.4:99999",
			wantLen: 0,
		},
		{
			name:    "port zero",
			body:    "1.2.3.4:0",
			wantLen: 0,
		},
		{
			name:    "negative port",
			body:    "1.2.3.4:-1",
			wantLen: 0,
		},
		{
			name:    "non-numeric port",
			body:    "1.2.3.4:abc",
			wantLen: 0,
		},
		{
			name:    "space inside host",
			body:    "1.2.3.4 5:8080",
			wantLen: 0,
		},
		{
			name:    "comma inside host",
			body:    "1.2.3.4,5:8080",
			wantLen: 0,
		},
		{
			name:    "slash inside host",
			body:    "1.2.3.4/5:8080",
			wantLen: 0,
		},
		{
			name:    "tab inside host",
			body:    "1.2.3.4\t5:8080",
			wantLen: 0,
		},
		{
			name:     "valid hostname",
			body:     "example.com:8080",
			wantLen:  1,
			wantHost: "example.com",
			wantPort: 8080,
		},
		{
			name:    "hostname longer than 253 characters",
			body:    strings.Repeat("a", 254) + ":8080",
			wantLen: 0,
		},
		{
			name:     "hostname exactly 253 characters",
			body:     strings.Repeat("b", 253) + ":80",
			wantLen:  1,
			wantHost: strings.Repeat("b", 253),
			wantPort: 80,
		},
		{
			name:    "port 65536 rejected",
			body:    "1.2.3.4:65536",
			wantLen: 0,
		},
		{
			name:     "port 65535 accepted",
			body:     "1.2.3.4:65535",
			wantLen:  1,
			wantHost: "1.2.3.4",
			wantPort: 65535,
		},
		{
			name:     "port 1 accepted",
			body:     "1.2.3.4:1",
			wantLen:  1,
			wantHost: "1.2.3.4",
			wantPort: 1,
		},
		{
			name:     "multiple valid lines",
			body:     "1.2.3.4:8080\n5.6.7.8:3128\n# comment\n\n9.10.11.12:1080",
			wantLen:  3,
			wantHost: "1.2.3.4",
			wantPort: 8080,
		},
		{
			name:    "ipv6 bracket notation skipped by simple parser",
			body:    "[::1]:8080",
			wantLen: 0,
		},
		{
			name:    "host with only colon no port",
			body:    "host:",
			wantLen: 0,
		},
		{
			name:    "port with no host",
			body:    ":8080",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{}
			result := s.parseTXT([]byte(tt.body), testSrc)

			if len(result) != tt.wantLen {
				t.Errorf("got %d proxies, want %d", len(result), tt.wantLen)
			}

			if tt.wantLen > 0 && len(result) > 0 {
				if result[0].Host != tt.wantHost {
					t.Errorf("Host = %q, want %q", result[0].Host, tt.wantHost)
				}
				if result[0].Port != tt.wantPort {
					t.Errorf("Port = %d, want %d", result[0].Port, tt.wantPort)
				}
				if result[0].Protocol != models.ProtoHTTP {
					t.Errorf("Protocol = %q, want %q", result[0].Protocol, models.ProtoHTTP)
				}
				if result[0].State != models.StateDiscovered {
					t.Errorf("State = %q, want %q", result[0].State, models.StateDiscovered)
				}
				if result[0].Source != testSrc.URL {
					t.Errorf("Source = %q, want %q", result[0].Source, testSrc.URL)
				}
			}
		})
	}
}

func TestParseTXT_ProtocolPropagation(t *testing.T) {
	s := &Scanner{}
	src := models.SourceConfig{
		URL:      "socks5-source",
		Protocol: models.ProtoSOCKS5,
	}

	result := s.parseTXT([]byte("10.0.0.1:1080"), src)
	if len(result) != 1 {
		t.Fatalf("got %d proxies, want 1", len(result))
	}
	if result[0].Protocol != models.ProtoSOCKS5 {
		t.Errorf("Protocol = %q, want %q", result[0].Protocol, models.ProtoSOCKS5)
	}
}

func TestParseJSON(t *testing.T) {
	testSrc := models.SourceConfig{
		URL:      "json-source",
		Protocol: models.ProtoHTTP,
	}

	tests := []struct {
		name     string
		body     string
		wantLen  int
		wantHost string
		wantPort int
	}{
		{
			name:     "valid json with ip field",
			body:     `[{"ip":"1.2.3.4","port":8080}]`,
			wantLen:  1,
			wantHost: "1.2.3.4",
			wantPort: 8080,
		},
		{
			name:     "valid json with host field",
			body:     `[{"host":"example.com","port":3128}]`,
			wantLen:  1,
			wantHost: "example.com",
			wantPort: 3128,
		},
		{
			name:     "both host and ip, host takes precedence",
			body:     `[{"host":"myhost.com","ip":"1.2.3.4","port":8080}]`,
			wantLen:  1,
			wantHost: "myhost.com",
			wantPort: 8080,
		},
		{
			name:    "empty json array",
			body:    `[]`,
			wantLen: 0,
		},
		{
			name:    "missing both host and ip",
			body:    `[{"port":8080}]`,
			wantLen: 0,
		},
		{
			name:    "port zero rejected",
			body:    `[{"ip":"1.2.3.4","port":0}]`,
			wantLen: 0,
		},
		{
			name:    "port too high rejected",
			body:    `[{"ip":"1.2.3.4","port":99999}]`,
			wantLen: 0,
		},
		{
			name:    "negative port rejected",
			body:    `[{"ip":"1.2.3.4","port":-1}]`,
			wantLen: 0,
		},
		{
			name:    "invalid json returns nil",
			body:    `not json at all`,
			wantLen: 0,
		},
		{
			name:    "null json returns nil",
			body:    `null`,
			wantLen: 0,
		},
		{
			name: "mixed valid and invalid entries",
			body: `[
				{"ip":"1.2.3.4","port":8080},
				{"port":9999},
				{"host":"example.com","port":3128}
			]`,
			wantLen:  2,
			wantHost: "1.2.3.4",
			wantPort: 8080,
		},
		{
			name:     "port string parsed as number by JSON decoder",
			body:     `[{"ip":"1.2.3.4","port":"8080"}]`,
			wantLen:  0,
		},
		{
			name:     "no port field",
			body:     `[{"ip":"1.2.3.4"}]`,
			wantLen:  0,
		},
		{
			name:    "host is empty string, ip is empty",
			body:    `[{"host":"","ip":"","port":8080}]`,
			wantLen: 0,
		},
		{
			name:     "host empty, ip has value",
			body:     `[{"host":"","ip":"10.0.0.1","port":3128}]`,
			wantLen:  1,
			wantHost: "10.0.0.1",
			wantPort: 3128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{}
			result := s.parseJSON([]byte(tt.body), testSrc)

			if len(result) != tt.wantLen {
				t.Errorf("got %d proxies, want %d", len(result), tt.wantLen)
			}

			if tt.wantLen > 0 && len(result) > 0 {
				if result[0].Host != tt.wantHost {
					t.Errorf("Host = %q, want %q", result[0].Host, tt.wantHost)
				}
				if result[0].Port != tt.wantPort {
					t.Errorf("Port = %d, want %d", result[0].Port, tt.wantPort)
				}
				if result[0].Protocol != models.ProtoHTTP {
					t.Errorf("Protocol = %q, want %q", result[0].Protocol, models.ProtoHTTP)
				}
				if result[0].State != models.StateDiscovered {
					t.Errorf("State = %q, want %q", result[0].State, models.StateDiscovered)
				}
			}
		})
	}
}

func TestDeduplicate(t *testing.T) {
	makeProxy := func(host string, port int) *models.Proxy {
		return &models.Proxy{Host: host, Port: port}
	}

	t.Run("new proxy is accepted", func(t *testing.T) {
		s := &Scanner{}
		seen := make(map[string]time.Time)

		proxies := []*models.Proxy{makeProxy("1.2.3.4", 8080)}
		result := s.deduplicate(proxies, seen)

		if len(result) != 1 {
			t.Fatalf("got %d proxies, want 1", len(result))
		}
		key := "1.2.3.4:8080"
		if _, ok := seen[key]; !ok {
			t.Error("proxy should be recorded in seen map")
		}
	})

	t.Run("proxy within seenTTL is rejected", func(t *testing.T) {
		s := &Scanner{}
		now := time.Now()
		key := "1.2.3.4:8080"
		seen := map[string]time.Time{
			key: now.Add(-10 * time.Minute), // 10 min ago, within 30 min TTL
		}

		proxies := []*models.Proxy{makeProxy("1.2.3.4", 8080)}
		result := s.deduplicate(proxies, seen)

		if len(result) != 0 {
			t.Errorf("got %d proxies, want 0 (within TTL)", len(result))
		}
	})

	t.Run("proxy outside seenTTL is re-accepted", func(t *testing.T) {
		s := &Scanner{}
		now := time.Now()
		key := "1.2.3.4:8080"
		oldTime := now.Add(-seenTTL - time.Minute) // 31 min ago, outside 30 min TTL
		seen := map[string]time.Time{key: oldTime}

		proxies := []*models.Proxy{makeProxy("1.2.3.4", 8080)}
		result := s.deduplicate(proxies, seen)

		if len(result) != 1 {
			t.Fatalf("got %d proxies, want 1 (outside TTL)", len(result))
		}
		if seen[key].Equal(oldTime) {
			t.Error("seen timestamp should be updated after re-acceptance")
		}
	})

	t.Run("exactly at seenTTL boundary is re-accepted", func(t *testing.T) {
		s := &Scanner{}
		now := time.Now()
		key := "5.6.7.8:3128"
		seen := map[string]time.Time{
			key: now.Add(-seenTTL + time.Second), // just inside TTL
		}

		proxies := []*models.Proxy{makeProxy("5.6.7.8", 3128)}
		result := s.deduplicate(proxies, seen)

		if len(result) != 0 {
			t.Errorf("got %d proxies, want 0 (within TTL)", len(result))
		}
	})

	t.Run("empty input returns empty", func(t *testing.T) {
		s := &Scanner{}
		seen := make(map[string]time.Time)

		result := s.deduplicate(nil, seen)
		if len(result) != 0 {
			t.Errorf("got %d proxies, want 0", len(result))
		}
	})

	t.Run("multiple proxies with mixed seen status", func(t *testing.T) {
		s := &Scanner{}
		now := time.Now()
		seen := map[string]time.Time{
			"old:8080": now.Add(-seenTTL - time.Hour),  // outside TTL -> accepted
			"new:8080": now.Add(-time.Minute),          // inside TTL -> rejected
		}

		proxies := []*models.Proxy{
			makeProxy("old", 8080),
			makeProxy("new", 8080),
			makeProxy("unseen", 8080), // never seen -> accepted
		}
		result := s.deduplicate(proxies, seen)

		if len(result) != 2 {
			t.Errorf("got %d proxies, want 2 (old and unseen)", len(result))
		}

		seenIDs := map[string]bool{}
		for _, p := range result {
			seenIDs[p.Host] = true
		}
		if !seenIDs["old"] {
			t.Error("'old' should have been accepted (outside TTL)")
		}
		if seenIDs["new"] {
			t.Error("'new' should have been rejected (inside TTL)")
		}
		if !seenIDs["unseen"] {
			t.Error("'unseen' should have been accepted (new)")
		}
	})
}
