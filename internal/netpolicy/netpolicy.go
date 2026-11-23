// Package netpolicy decides which network destinations proxier may connect to
// as a proxy. Free proxy lists and API callers can name arbitrary addresses.
// By default proxier refuses loopback, private, link-local, shared (CGNAT),
// unspecified, reserved and multicast destinations, so that a hostile list
// or caller cannot make the validator reach services on the host or its
// network. Operators who run proxies on such addresses opt in with
// validator.allow_private_proxies.
package netpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
)

// ErrDisallowed is returned for destinations the policy refuses.
var ErrDisallowed = errors.New("destination address is not allowed (loopback, private or reserved)")

var extraBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),      // shared address space (CGNAT, tailnets)
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved
	netip.MustParsePrefix("255.255.255.255/32"), // broadcast
}

// Disallowed reports whether ip is refused by the default policy.
func Disallowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, p := range extraBlocked {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckHost applies the policy to a host that is an IP literal. Host names
// pass here; their resolved addresses are checked at dial time by Control.
func CheckHost(host string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if err != nil {
		return nil
	}
	if Disallowed(ip) {
		return fmt.Errorf("%w: %s", ErrDisallowed, ip)
	}
	return nil
}

// Control returns a net.Dialer Control function that enforces the policy on
// the address actually being connected to, after DNS resolution. Checking
// there (rather than the name) also defeats DNS rebinding. It returns nil
// when private destinations are allowed.
func Control(allowPrivate bool) func(network, address string, c syscall.RawConn) error {
	if allowPrivate {
		return nil
	}
	return func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrDisallowed, address)
		}
		if Disallowed(ap.Addr()) {
			return fmt.Errorf("%w: %s", ErrDisallowed, ap.Addr())
		}
		return nil
	}
}
