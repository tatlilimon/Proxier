// Package fakeproxy provides loopback test fixtures: an httpbin-style probe,
// forward proxies (HTTP with CONNECT, SOCKS4, SOCKS5) and misbehaving
// variants. It is imported only by tests.
//
// Each proxy dials upstream from its own egress address in 127.0.0.0/8
// (Linux routes the whole block to loopback), so the probe sees a different
// client address through the proxy than without it — like a real proxy.
package fakeproxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Probe reports the caller's address like httpbin.org/ip. It prepends an
// X-Forwarded-For header, as httpbin does, so a proxy that forwards the
// client's address is visible in the origin list.
type Probe struct {
	*httptest.Server
	hits atomic.Int64
}

// NewProbe starts a probe; withTLS uses httptest's certificate.
func NewProbe(t testing.TB, withTLS bool) *Probe {
	t.Helper()
	p := &Probe{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		origin := host
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			origin = xff + ", " + host
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"origin": %q}`, origin)
	})
	if withTLS {
		p.Server = httptest.NewTLSServer(h)
	} else {
		p.Server = httptest.NewServer(h)
	}
	t.Cleanup(p.Close)
	return p
}

// Hits returns how many requests reached the probe.
func (p *Probe) Hits() int64 { return p.hits.Load() }

// RootCAs trusts the probe's certificate.
func (p *Probe) RootCAs() *x509.CertPool {
	roots := x509.NewCertPool()
	if c := p.Certificate(); c != nil {
		roots.AddCert(c)
	}
	return roots
}

// IP returns the probe's IP address.
func (p *Probe) IP() string {
	host, _, _ := net.SplitHostPort(p.Listener.Addr().String())
	return host
}

// Proxy is a running fixture.
type Proxy struct {
	Host string
	Port int

	l       net.Listener
	srv     *http.Server
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closed  atomic.Bool
	Handled atomic.Int64
}

// Addr returns host:port.
func (p *Proxy) Addr() string { return net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) }

// Close stops the fixture and drops open connections.
func (p *Proxy) Close() {
	if p.closed.Swap(true) {
		return
	}
	if p.srv != nil {
		p.srv.Close()
	}
	p.l.Close()
	p.mu.Lock()
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
}

func (p *Proxy) track(c net.Conn) {
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

func listen(t testing.TB) (*Proxy, net.Listener) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(l.Addr().String())
	n, _ := strconv.Atoi(port)
	p := &Proxy{Host: host, Port: n, l: l, conns: map[net.Conn]struct{}{}}
	t.Cleanup(p.Close)
	return p, l
}

func egressDialer(egress string) *net.Dialer {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if egress != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(egress)}
	}
	return d
}

// HTTPOptions selects misbehaviour of an HTTP proxy.
type HTTPOptions struct {
	// Egress is the source address for upstream connections.
	Egress string
	// ForwardClient adds X-Forwarded-For with the client's address (a
	// transparent proxy that leaks the client).
	ForwardClient bool
	// Body, if set, is returned with status 200 for every request instead
	// of forwarding (a captive portal or a fake answer).
	Body string
	// RedirectTo, if set, answers every request with a 302 to this URL.
	RedirectTo string
	// MITM terminates CONNECT tunnels with its own untrusted certificate
	// and answers with Body (or a forged origin).
	MITM bool
	// TLS serves the proxy itself over TLS (an "https" proxy) with an
	// untrusted certificate.
	TLS bool
}

// NewHTTPProxy starts an HTTP forward proxy that supports absolute-form
// requests and CONNECT.
func NewHTTPProxy(t testing.TB, o HTTPOptions) *Proxy {
	t.Helper()
	p, l := listen(t)
	dialer := egressDialer(o.Egress)
	upstream := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
	var mitmCert tls.Certificate
	if o.MITM || o.TLS {
		mitmCert = selfSigned(t)
	}

	p.srv = &http.Server{
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				p.track(c)
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.Handled.Add(1)
			switch {
			case o.RedirectTo != "":
				http.Redirect(w, r, o.RedirectTo, http.StatusFound)
				return
			case o.Body != "" && r.Method != http.MethodConnect:
				fmt.Fprint(w, o.Body)
				return
			}

			if r.Method == http.MethodConnect {
				hj, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "no hijack", http.StatusInternalServerError)
					return
				}
				client, _, err := hj.Hijack()
				if err != nil {
					return
				}
				defer client.Close()
				if o.MITM {
					io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
					tc := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{mitmCert}})
					defer tc.Close()
					if err := tc.Handshake(); err != nil {
						return
					}
					body := o.Body
					if body == "" {
						body = `{"origin": "203.0.113.99"}`
					}
					fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
					return
				}
				up, err := dialer.Dial("tcp", r.Host)
				if err != nil {
					io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
				pipe(client, up)
				return
			}

			out := r.Clone(r.Context())
			out.RequestURI = ""
			if o.ForwardClient {
				host, _, _ := net.SplitHostPort(r.RemoteAddr)
				out.Header.Set("X-Forwarded-For", host)
			}
			resp, err := upstream.RoundTrip(out)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for k, vs := range resp.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}),
	}
	if o.TLS {
		p.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{mitmCert}}
		go p.srv.ServeTLS(l, "", "")
	} else {
		go p.srv.Serve(l)
	}
	return p
}

// NewSOCKS5 starts a no-authentication SOCKS5 proxy (CONNECT only).
func NewSOCKS5(t testing.TB, egress string) *Proxy {
	t.Helper()
	p, l := listen(t)
	dialer := egressDialer(egress)
	go acceptLoop(p, l, func(c net.Conn) {
		br := bufio.NewReader(c)
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 {
			return
		}
		if _, err := io.ReadFull(br, make([]byte, hdr[1])); err != nil {
			return
		}
		c.Write([]byte{5, 0})
		req := make([]byte, 4)
		if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
			return
		}
		var host string
		switch req[3] {
		case 1:
			b := make([]byte, 4)
			io.ReadFull(br, b)
			host = net.IP(b).String()
		case 3:
			n, _ := br.ReadByte()
			b := make([]byte, n)
			io.ReadFull(br, b)
			host = string(b)
		case 4:
			b := make([]byte, 16)
			io.ReadFull(br, b)
			host = net.IP(b).String()
		default:
			return
		}
		pb := make([]byte, 2)
		io.ReadFull(br, pb)
		target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
		up, err := dialer.Dial("tcp", target)
		if err != nil {
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		p.Handled.Add(1)
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		pipe(&bufConn{Conn: c, r: br}, up)
	})
	return p
}

// NewSOCKS4 starts a SOCKS4/SOCKS4a proxy (CONNECT only).
func NewSOCKS4(t testing.TB, egress string) *Proxy {
	t.Helper()
	p, l := listen(t)
	dialer := egressDialer(egress)
	go acceptLoop(p, l, func(c net.Conn) {
		br := bufio.NewReader(c)
		req := make([]byte, 8)
		if _, err := io.ReadFull(br, req); err != nil || req[0] != 4 || req[1] != 1 {
			return
		}
		if _, err := br.ReadString(0); err != nil { // user ID
			return
		}
		port := int(binary.BigEndian.Uint16(req[2:4]))
		host := net.IP(req[4:8]).String()
		if req[4] == 0 && req[5] == 0 && req[6] == 0 && req[7] != 0 {
			name, err := br.ReadString(0)
			if err != nil {
				return
			}
			host = strings.TrimSuffix(name, "\x00")
		}
		up, err := dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			c.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		p.Handled.Add(1)
		c.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0})
		pipe(&bufConn{Conn: c, r: br}, up)
	})
	return p
}

// NewStall accepts connections and never answers.
func NewStall(t testing.TB) *Proxy {
	t.Helper()
	p, l := listen(t)
	go acceptLoop(p, l, func(c net.Conn) {
		p.Handled.Add(1)
		io.Copy(io.Discard, c)
	})
	return p
}

// FirstByte accepts one connection and reports the first byte received.
func FirstByte(t testing.TB) (*Proxy, <-chan byte) {
	t.Helper()
	p, l := listen(t)
	ch := make(chan byte, 1)
	go acceptLoop(p, l, func(c net.Conn) {
		var b [1]byte
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(b[:]); err == nil {
			select {
			case ch <- b[0]:
			default:
			}
		}
	})
	return p, ch
}

func acceptLoop(p *Proxy, l net.Listener, handle func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		p.track(c)
		go func() {
			defer c.Close()
			handle(c)
		}()
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

func selfSigned(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "untrusted interceptor"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost", "example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ListServer serves proxy lists; Set changes what a path returns.
type ListServer struct {
	*httptest.Server
	mu    sync.Mutex
	lists map[string]string
}

// NewListServer starts an empty list server.
func NewListServer(t testing.TB) *ListServer {
	t.Helper()
	s := &ListServer{lists: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, ok := s.lists[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

// Set makes path return body.
func (s *ListServer) Set(path, body string) {
	s.mu.Lock()
	s.lists[path] = body
	s.mu.Unlock()
}
