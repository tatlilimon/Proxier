package models

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ProxyState represents the lifecycle state of a proxy.
type ProxyState string

const (
	// StateDiscovered: known candidate that has not been checked yet.
	StateDiscovered ProxyState = "DISCOVERED"
	// StateValidating: not in rotation; waiting for (another) check after a
	// failure, after a restart, or because its last success is stale.
	StateValidating ProxyState = "VALIDATING"
	// StateAlive: passed its most recent check; available for rotation.
	StateAlive ProxyState = "ALIVE"
	// StateDead: failed MaxConsecutiveFails checks in a row.
	StateDead ProxyState = "DEAD"
)

// Protocol represents the proxy protocol type.
type Protocol string

const (
	ProtoHTTP   Protocol = "http"
	ProtoHTTPS  Protocol = "https"
	ProtoSOCKS4 Protocol = "socks4"
	ProtoSOCKS5 Protocol = "socks5"

	// ProtoMixed is only valid for sources: each line may name its own scheme
	// (socks5://host:port); unprefixed lines are tried as http, socks4 and
	// socks5. A proxy record never has this protocol.
	ProtoMixed Protocol = "mixed"
)

// ProxyProtocols lists every protocol a proxy record can have.
var ProxyProtocols = []Protocol{ProtoHTTP, ProtoHTTPS, ProtoSOCKS4, ProtoSOCKS5}

// MixedProtocols are tried for an unprefixed line of a "mixed" source.
var MixedProtocols = []Protocol{ProtoHTTP, ProtoSOCKS4, ProtoSOCKS5}

// Valid reports whether p is a protocol a proxy record can have.
func (p Protocol) Valid() bool {
	switch p {
	case ProtoHTTP, ProtoHTTPS, ProtoSOCKS4, ProtoSOCKS5:
		return true
	}
	return false
}

// ValidSource reports whether p may be configured for a source.
func (p Protocol) ValidSource() bool {
	return p.Valid() || p == ProtoMixed
}

// ParseScheme maps a URL scheme to a proxy protocol. socks4a and socks5h are
// accepted as aliases because the dialers always resolve names remotely.
func ParseScheme(scheme string) (Protocol, bool) {
	switch strings.ToLower(scheme) {
	case "http":
		return ProtoHTTP, true
	case "https":
		return ProtoHTTPS, true
	case "socks4", "socks4a":
		return ProtoSOCKS4, true
	case "socks5", "socks5h":
		return ProtoSOCKS5, true
	}
	return "", false
}

// Anonymity represents the anonymity level of a proxy. Proxier does not
// classify anonymity yet; the field is kept for storage compatibility.
type Anonymity string

const (
	AnonTransparent Anonymity = "transparent"
	AnonAnonymous   Anonymity = "anonymous"
	AnonElite       Anonymity = "elite"
)

// Proxy represents a single proxy record in the system.
type Proxy struct {
	ID              string     `json:"id"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	Protocol        Protocol   `json:"protocol"`
	State           ProxyState `json:"state"`
	HealthScore     float64    `json:"health_score"`
	LatencyMs       int        `json:"latency_ms"`
	Country         string     `json:"country,omitempty"`
	Anonymity       Anonymity  `json:"anonymity,omitempty"`
	ConsecutiveOK   int        `json:"consecutive_ok"`
	ConsecutiveFail int        `json:"consecutive_fail"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastChecked     time.Time  `json:"last_checked"`
	Source          string     `json:"source"`

	// LastSuccess is the time of the most recent successful check.
	LastSuccess time.Time `json:"last_success,omitzero"`
	// DiedAt is when the proxy last became DEAD (zero while it is not dead).
	DiedAt time.Time `json:"died_at,omitzero"`
	// NextCheck is when the proxy is due for its next check. A zero value
	// means "now" for every state except DEAD, where it means "never" (until
	// a source lists the proxy again).
	NextCheck time.Time `json:"next_check,omitzero"`

	// Version is the pool's mutation counter at the record's last change and
	// Dirty marks changes not yet acknowledged by storage. Both are
	// runtime-only.
	Version uint64 `json:"-"`
	Dirty   bool   `json:"-"`
}

// NormalizeHost returns the canonical form used for identity: lower-case,
// without IPv6 brackets, and IP literals in their shortest form.
func NormalizeHost(host string) string {
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return strings.ToLower(host)
}

// ProxyID generates the deterministic record ID. The protocol is part of the
// identity: an address that speaks both HTTP and SOCKS5 is two records.
func ProxyID(protocol Protocol, host string, port int) string {
	raw := string(protocol) + "://" + net.JoinHostPort(NormalizeHost(host), strconv.Itoa(port))
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash[:16])
}

// LegacyProxyID is the identity used before protocols were part of it. It is
// only needed to migrate stored records.
func LegacyProxyID(host string, port int) string {
	raw := fmt.Sprintf("%s:%d", host, port)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash[:16])
}

// NewCandidate builds a DISCOVERED record with a normalized host and its ID.
func NewCandidate(protocol Protocol, host string, port int, source string, now time.Time) Proxy {
	host = NormalizeHost(host)
	return Proxy{
		ID:        ProxyID(protocol, host, port),
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		State:     StateDiscovered,
		Source:    source,
		FirstSeen: now.UTC(),
	}
}

// Address returns the host:port formatted address (IPv6 hosts in brackets).
func (p *Proxy) Address() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

// URL returns the full proxy URL (e.g., http://host:port).
func (p *Proxy) URL() string {
	return string(p.Protocol) + "://" + p.Address()
}
