package socks4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// serve accepts one connection, records the request and answers with reply.
func serve(t *testing.T, reply []byte) (addr string, got <-chan []byte) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	ch := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := c.Read(buf)
		ch <- buf[:n]
		if reply != nil {
			c.Write(reply)
		}
		// Keep the connection open (a stalled proxy when reply is nil).
		c.SetReadDeadline(time.Time{})
		io.Copy(io.Discard, c)
	}()
	return l.Addr().String(), ch
}

func TestDialContextSendsSOCKS4ForIPv4Target(t *testing.T) {
	addr, got := serve(t, []byte{0, 90, 0, 0, 0, 0, 0, 0})
	conn, err := DialContext(context.Background(), &net.Dialer{}, addr, "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	want := []byte{4, 1, 0x01, 0xBB, 93, 184, 216, 34, 0}
	if req := <-got; !bytes.Equal(req, want) {
		t.Errorf("request = %v, want %v", req, want)
	}
}

func TestDialContextUsesSOCKS4aForHostNames(t *testing.T) {
	addr, got := serve(t, []byte{0, 90, 0, 0, 0, 0, 0, 0})
	conn, err := DialContext(context.Background(), &net.Dialer{}, addr, "httpbin.org:80")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	want := append([]byte{4, 1, 0, 80, 0, 0, 0, 1, 0}, append([]byte("httpbin.org"), 0)...)
	if req := <-got; !bytes.Equal(req, want) {
		t.Errorf("request = %v, want %v", req, want)
	}
}

func TestDialContextRejectedRequest(t *testing.T) {
	addr, _ := serve(t, []byte{0, 91, 0, 0, 0, 0, 0, 0})
	if _, err := DialContext(context.Background(), &net.Dialer{}, addr, "1.2.3.4:80"); err == nil {
		t.Fatal("rejected request returned a connection")
	}
}

func TestDialContextRefusesIPv6Target(t *testing.T) {
	if _, err := DialContext(context.Background(), &net.Dialer{}, "127.0.0.1:1", "[2001:db8::1]:80"); !errors.Is(err, ErrIPv6Target) {
		t.Fatalf("err = %v, want ErrIPv6Target", err)
	}
}

// A proxy that accepts the connection and never answers must not keep the
// dial alive past the context deadline.
func TestDialContextHonoursDeadlineWhenProxyStalls(t *testing.T) {
	addr, _ := serve(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := DialContext(ctx, &net.Dialer{}, addr, "1.2.3.4:80")
	if err == nil {
		t.Fatal("stalled proxy returned a connection")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dial returned after %s, want shortly after the 50ms deadline", elapsed)
	}
}

func TestDialContextHonoursCancellation(t *testing.T) {
	addr, _ := serve(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := DialContext(ctx, &net.Dialer{}, addr, "1.2.3.4:80")
		done <- err
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial still blocked after cancellation")
	}
}
