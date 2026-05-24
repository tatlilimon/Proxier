// Package socks4 provides a minimal SOCKS4/SOCKS4a CONNECT dialer.
//
// It is designed for the proxier validator — it dials the proxy, performs the
// SOCKS4 handshake, and returns the net.Conn ready for the HTTP exchange.
package socks4

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// Dial connects to proxyAddr, performs a SOCKS4/SOCKS4a CONNECT handshake
// targeting targetHost:targetPort, and returns the underlying net.Conn.
//
// SOCKS4a (hostname destinations) is detected automatically when targetHost
// is not a valid IPv4 address.
func Dial(ctx context.Context, targetHost string, targetPort int, proxyAddr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS4 connect to %s: %w", proxyAddr, err)
	}

	// Build SOCKS4/SOCKS4a CONNECT request.
	// Format: [VN=4, CD=1, DSTPORT(2 BE), DSTIP(4), USERID\0, (SOCKS4a: HOSTNAME\0)]
	var req []byte
	dstIP := net.ParseIP(targetHost)
	if dstIP != nil && dstIP.To4() != nil {
		// Standard SOCKS4: destination is an IPv4 address.
		req = make([]byte, 0, 9)
		req = append(req, 4, 1) // VN=4, CD=1 (CONNECT)
		req = append(req, byte(targetPort>>8), byte(targetPort&0xFF))
		req = append(req, dstIP.To4()...)
		req = append(req, 0) // empty user ID
	} else {
		// SOCKS4a: destination is a hostname; encode as 0.0.0.x.
		req = make([]byte, 0, 9+len(targetHost)+1)
		req = append(req, 4, 1) // VN=4, CD=1 (CONNECT)
		req = append(req, byte(targetPort>>8), byte(targetPort&0xFF))
		req = append(req, 0, 0, 0, 1) // 0.0.0.x (non-zero last byte signals SOCKS4a)
		req = append(req, 0)            // empty user ID
		req = append(req, []byte(targetHost)...)
		req = append(req, 0) // null terminator for hostname
	}

	// Set write/read deadline for the handshake.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 write request: %w", err)
	}

	// Read the 8-byte SOCKS4 response: [VN, CD, DSTPORT(2), DSTIP(4)]
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 read response: %w", err)
	}

	// Clear the deadline after handshake so the HTTP exchange can proceed.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	// CD (reply code): 90 = granted, 91 = rejected, 92 = identd, 93 = identd mismatch
	if resp[1] != 90 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 request rejected: CD=%d", resp[1])
	}

	return conn, nil
}
