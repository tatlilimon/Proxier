package storage

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tatlilimon/proxier/internal/models"
)

// legacyDB creates a database exactly like the original schema (version 0)
// with records keyed by the old host:port identity.
func legacyDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxies.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS proxies (
		id TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
		state TEXT NOT NULL, health_score REAL NOT NULL DEFAULT 0, latency_ms INTEGER NOT NULL DEFAULT 0,
		country TEXT DEFAULT '', anonymity TEXT DEFAULT '', consecutive_ok INTEGER NOT NULL DEFAULT 0,
		consecutive_fail INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_checked TEXT NOT NULL,
		source TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO proxies (id, host, port, protocol, state, health_score, latency_ms, country, anonymity,
		consecutive_ok, consecutive_fail, first_seen, last_checked, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	rows := []struct {
		host, proto, state string
		port               int
	}{
		{"198.51.100.1", "http", "ALIVE", 8080},
		{"Proxy.Example", "socks5", "DEAD", 1080},
		{"198.51.100.2", "socks4", "VALIDATING", 1080},
	}
	for _, r := range rows {
		if _, err := db.Exec(ins, models.LegacyProxyID(r.host, r.port), r.host, r.port, r.proto, r.state,
			0.7, 120, nil, nil, 4, 0, "2026-08-01T10:00:00Z", "2026-09-06T20:00:00Z", "src"); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestMigrateLegacyDatabase(t *testing.T) {
	path := legacyDB(t)

	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	got, err := s.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if len(got) != 3 {
		t.Fatalf("loaded %d records, want 3", len(got))
	}
	for _, p := range got {
		if p.ID != models.ProxyID(p.Protocol, p.Host, p.Port) {
			t.Errorf("record %s was not re-keyed (id %s)", p.URL(), p.ID)
		}
		if p.Host == "Proxy.Example" {
			t.Error("host name was not normalized")
		}
		if !p.LastSuccess.IsZero() || !p.DiedAt.IsZero() || !p.NextCheck.IsZero() {
			t.Errorf("new columns should start empty: %+v", p)
		}
		if p.ConsecutiveOK != 4 || p.LastChecked.IsZero() || p.Source != "src" {
			t.Errorf("history lost in migration: %+v", p)
		}
	}

	// Reopening is a no-op and keeps the same records.
	s, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := s.LoadAll()
	var version int
	s.(*sqliteStore).db.QueryRow(`PRAGMA user_version`).Scan(&version)
	s.Close()
	if len(again) != 3 || version != SchemaVersion {
		t.Fatalf("reopen: %d records, schema %d", len(again), version)
	}
}

func TestApplyRoundTripAndDelete(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().Truncate(time.Microsecond)
	a := models.NewCandidate(models.ProtoSOCKS5, "2001:db8::1", 1080, "src", now)
	a.State, a.LastChecked, a.LastSuccess, a.NextCheck = models.StateAlive, now, now, now.Add(time.Minute)
	b := models.NewCandidate(models.ProtoHTTP, "198.51.100.9", 80, "src", now)
	b.State, b.DiedAt = models.StateDead, now

	if err := s.Apply([]*models.Proxy{&a, &b}, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := s.LoadAll()
	byID := map[string]*models.Proxy{}
	for _, p := range got {
		byID[p.ID] = p
	}
	if ga := byID[a.ID]; ga == nil || !ga.LastSuccess.Equal(now) || !ga.NextCheck.Equal(a.NextCheck) || ga.Address() != "[2001:db8::1]:1080" {
		t.Fatalf("round trip of a = %+v", ga)
	}
	if gb := byID[b.ID]; gb == nil || !gb.DiedAt.Equal(now) || !gb.LastSuccess.IsZero() {
		t.Fatalf("round trip of b = %+v", gb)
	}

	if err := s.Apply(nil, []string{b.ID}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadAll(); len(got) != 1 || got[0].ID != a.ID {
		t.Fatalf("after delete: %+v", got)
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	db, _ := sql.Open("sqlite", path)
	db.Exec(`PRAGMA user_version = 99`)
	db.Close()
	if _, err := NewSQLiteStore(path); err == nil {
		t.Fatal("opened a database with a newer schema")
	}
}

func TestCorruptFileIsRefusedAndLeftAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	junk := bytes.Repeat([]byte("not a database "), 400)
	if err := os.WriteFile(path, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(path); err == nil {
		t.Fatal("opened a corrupt file")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, junk) {
		t.Fatal("the corrupt file was modified")
	}
}

func TestNewRejectsUnsupportedBackend(t *testing.T) {
	if _, err := New("json", "x"); err == nil {
		t.Fatal("json backend accepted")
	}
}
