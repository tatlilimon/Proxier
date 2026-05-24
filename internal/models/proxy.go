package models

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// ProxyState represents the lifecycle state of a proxy.
type ProxyState string

const (
	StateDiscovered  ProxyState = "DISCOVERED"
	StateValidating  ProxyState = "VALIDATING"
	StateAlive       ProxyState = "ALIVE"
	StateDead        ProxyState = "DEAD"
)

// Protocol represents the proxy protocol type.
type Protocol string

const (
	ProtoHTTP   Protocol = "http"
	ProtoHTTPS  Protocol = "https"
	ProtoSOCKS4 Protocol = "socks4"
	ProtoSOCKS5 Protocol = "socks5"
)

// Anonymity represents the anonymity level of a proxy.
type Anonymity string

const (
	AnonTransparent Anonymity = "transparent"
	AnonAnonymous   Anonymity = "anonymous"
	AnonElite       Anonymity = "elite"
)

// Proxy represents a single proxy record in the system.
type Proxy struct {
	ID              string    `json:"id"`
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Protocol        Protocol  `json:"protocol"`
	State           ProxyState `json:"state"`
	HealthScore     float64   `json:"health_score"`
	LatencyMs       int       `json:"latency_ms"`
	Country         string    `json:"country,omitempty"`
	Anonymity       Anonymity `json:"anonymity,omitempty"`
	ConsecutiveOK   int       `json:"consecutive_ok"`
	ConsecutiveFail int       `json:"consecutive_fail"`
	FirstSeen       time.Time `json:"first_seen"`
	LastChecked     time.Time `json:"last_checked"`
	Source          string    `json:"source"`

	// Dirty is true when the proxy has been modified since the last persistence
	// flush. It is not persisted to storage — runtime-only.
	Dirty bool `json:"-"`
}

// ProxyID generates a deterministic unique ID for a host:port combination.
func ProxyID(host string, port int) string {
	raw := fmt.Sprintf("%s:%d", host, port)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash[:16])
}

// Address returns the host:port formatted address.
func (p *Proxy) Address() string {
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

// URL returns the full proxy URL (e.g., http://host:port).
func (p *Proxy) URL() string {
	return fmt.Sprintf("%s://%s:%d", p.Protocol, p.Host, p.Port)
}
