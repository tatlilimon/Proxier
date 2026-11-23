// Package socks4 provides a minimal SOCKS4/SOCKS4a CONNECT dialer.
//
// It is designed for the proxier validator: it dials the proxy, performs the
// SOCKS4 handshake for the requested target, and returns the connection ready
// for the HTTP exchange.
package socks4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// ContextDialer is the part of net.Dialer used to reach the proxy.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ErrIPv6Target is returned for IPv6 destinations, which SOCKS4 cannot
// express.
var ErrIPv6Target = errors.New("SOCKS4 cannot connect to IPv6 destinations")

// DialContext connects to proxyAddr with d, asks the proxy to CONNECT to
// target ("host:port") and returns the established connection.
//
// An IPv4 target uses SOCKS4; a host name uses SOCKS4a, so the proxy resolves
// it. The handshake honours ctx: its deadline bounds a proxy that accepts the
// connection but never answers, and cancellation aborts it immediately.
func DialContext(ctx context.Context, d ContextDialer, proxyAddr, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("SOCKS4 target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("SOCKS4 target port %q is invalid", portStr)
	}

	req, err := buildRequest(host, port)
	if err != nil {
		return nil, err
	}

	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS4 connect to %s: %w", proxyAddr, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
	}
	// Unblock the handshake as soon as ctx is cancelled.
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(time.Unix(1, 0))
	})

	resp := make([]byte, 8)
	_, err = conn.Write(req)
	if err == nil {
		_, err = io.ReadFull(conn, resp)
	}
	if !stop() {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 handshake with %s: %w", proxyAddr, ctx.Err())
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 handshake with %s: %w", proxyAddr, err)
	}

	// Reply: [VN=0, CD, DSTPORT(2), DSTIP(4)]. Some servers echo VN=4.
	if resp[0] != 0 && resp[0] != 4 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 reply has version %d", resp[0])
	}
	// CD: 90 granted, 91 rejected, 92/93 identd problems.
	if resp[1] != 90 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 request rejected: CD=%d", resp[1])
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// buildRequest encodes a CONNECT request:
// [VN=4, CD=1, DSTPORT(2 BE), DSTIP(4), USERID\0, (SOCKS4a: HOSTNAME\0)].
func buildRequest(host string, port int) ([]byte, error) {
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		return nil, ErrIPv6Target
	}

	req := make([]byte, 0, 10+len(host))
	req = append(req, 4, 1, byte(port>>8), byte(port&0xFF))
	if ip != nil {
		req = append(req, ip.To4()...)
		req = append(req, 0) // empty user ID
		return req, nil
	}
	if host == "" || len(host) > 255 {
		return nil, fmt.Errorf("SOCKS4a host name %q is invalid", host)
	}
	// SOCKS4a: 0.0.0.x with non-zero x, then the host name.
	req = append(req, 0, 0, 0, 1, 0)
	req = append(req, host...)
	req = append(req, 0)
	return req, nil
}
