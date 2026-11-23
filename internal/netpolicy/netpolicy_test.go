package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDisallowed(t *testing.T) {
	refused := []string{
		"127.0.0.1", "127.8.8.8", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "fe80::1", "fc00::1", "0.0.0.0", "::", "100.64.0.1",
		"100.127.255.254", "224.0.0.1", "ff02::1", "255.255.255.255", "240.0.0.1",
		"198.18.0.1", "192.0.0.8", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
	}
	for _, s := range refused {
		if !Disallowed(netip.MustParseAddr(s)) {
			t.Errorf("Disallowed(%s) = false, want true", s)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "203.0.113.7", "198.51.100.2", "2606:4700::1111", "100.128.0.1"}
	for _, s := range allowed {
		if Disallowed(netip.MustParseAddr(s)) {
			t.Errorf("Disallowed(%s) = true, want false", s)
		}
	}
}

func TestCheckHost(t *testing.T) {
	if err := CheckHost("127.0.0.1", false); !errors.Is(err, ErrDisallowed) {
		t.Errorf("loopback literal: err = %v, want ErrDisallowed", err)
	}
	if err := CheckHost("[::1]", false); !errors.Is(err, ErrDisallowed) {
		t.Errorf("bracketed IPv6 loopback: err = %v, want ErrDisallowed", err)
	}
	if err := CheckHost("127.0.0.1", true); err != nil {
		t.Errorf("opt-in must allow loopback, got %v", err)
	}
	if err := CheckHost("proxy.example", false); err != nil {
		t.Errorf("host names are checked at dial time, got %v", err)
	}
	if err := CheckHost("1.1.1.1", false); err != nil {
		t.Errorf("public address refused: %v", err)
	}
}

// TestControlRefusesResolvedLoopback proves the dial-time check: a name that
// resolves to loopback ("localhost") is refused even though the name itself
// is not an IP literal.
func TestControlRefusesResolvedLoopback(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())

	d := net.Dialer{Timeout: time.Second, Control: Control(false)}
	if _, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port)); !errors.Is(err, ErrDisallowed) {
		t.Fatalf("dial localhost: err = %v, want ErrDisallowed", err)
	}

	open := net.Dialer{Timeout: time.Second, Control: Control(true)}
	c, err := open.DialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("opt-in dial: %v", err)
	}
	c.Close()
}
