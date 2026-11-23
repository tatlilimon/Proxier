package storage

import (
	"database/sql"
	"fmt"
	"net/url"
	"time"

	"github.com/tatlilimon/proxier/internal/models"

	_ "modernc.org/sqlite"
)

// SchemaVersion is the schema this code reads and writes (PRAGMA
// user_version).
//
//	0: original table (identity = host:port)
//	1: identity includes the protocol; last_success, died_at and next_check
const SchemaVersion = 1

type sqliteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (creating if needed) the database at path, checks its
// integrity and migrates it to SchemaVersion.
func NewSQLiteStore(path string) (Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// One connection: a single writer, and the pragmas apply to it.
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}

	var check string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&check); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: integrity check: %w", err)
	}
	if check != "ok" {
		db.Close()
		return nil, fmt.Errorf("sqlite: integrity check failed for %s: %s (restore a backup; the file was not modified)", path, check)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("sqlite: read schema version: %w", err)
	}
	if version > SchemaVersion {
		return fmt.Errorf("sqlite: database schema version %d is newer than this build supports (%d)", version, SchemaVersion)
	}
	if version == SchemaVersion {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("sqlite: begin migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS proxies (
		id               TEXT PRIMARY KEY,
		host             TEXT NOT NULL,
		port             INTEGER NOT NULL,
		protocol         TEXT NOT NULL,
		state            TEXT NOT NULL,
		health_score     REAL NOT NULL DEFAULT 0,
		latency_ms       INTEGER NOT NULL DEFAULT 0,
		country          TEXT DEFAULT '',
		anonymity        TEXT DEFAULT '',
		consecutive_ok   INTEGER NOT NULL DEFAULT 0,
		consecutive_fail INTEGER NOT NULL DEFAULT 0,
		first_seen       TEXT NOT NULL,
		last_checked     TEXT NOT NULL,
		source           TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		return fmt.Errorf("sqlite: create table: %w", err)
	}

	if version < 1 {
		cols, err := columns(tx)
		if err != nil {
			return err
		}
		for _, c := range []string{"last_success", "died_at", "next_check"} {
			if !cols[c] {
				if _, err := tx.Exec(`ALTER TABLE proxies ADD COLUMN ` + c + ` TEXT NOT NULL DEFAULT ''`); err != nil {
					return fmt.Errorf("sqlite: add column %s: %w", c, err)
				}
			}
		}
		if err := rekey(tx); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion)); err != nil {
		return fmt.Errorf("sqlite: set schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit migration: %w", err)
	}
	return nil
}

func columns(tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.Query(`PRAGMA table_info(proxies)`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: table info: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var (
			cid, notNull, pk int
			name, typ        string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, fmt.Errorf("sqlite: table info: %w", err)
		}
		out[name] = true
	}
	return out, rows.Err()
}

// rekey moves every record to its protocol-aware ID and normalized host. Two
// old records that normalize to the same identity (host names differing only
// in case) collapse into one.
func rekey(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT id, host, port, protocol FROM proxies`)
	if err != nil {
		return fmt.Errorf("sqlite: read identities: %w", err)
	}
	type ident struct {
		id, host, proto string
		port            int
	}
	var all []ident
	for rows.Next() {
		var r ident
		if err := rows.Scan(&r.id, &r.host, &r.port, &r.proto); err != nil {
			rows.Close()
			return fmt.Errorf("sqlite: read identities: %w", err)
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, r := range all {
		host := models.NormalizeHost(r.host)
		id := models.ProxyID(models.Protocol(r.proto), host, r.port)
		if id == r.id && host == r.host {
			continue
		}
		if _, err := tx.Exec(`UPDATE OR REPLACE proxies SET id = ?, host = ? WHERE id = ?`, id, host, r.id); err != nil {
			return fmt.Errorf("sqlite: rekey %s: %w", r.id, err)
		}
	}
	return nil
}

const upsertSQL = `INSERT OR REPLACE INTO proxies
	(id, host, port, protocol, state, health_score, latency_ms, country, anonymity,
	 consecutive_ok, consecutive_fail, first_seen, last_checked, source,
	 last_success, died_at, next_check)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// Apply writes upserts and deletes in a single transaction.
func (s *sqliteStore) Apply(upserts []*models.Proxy, deletes []string) error {
	if len(upserts) == 0 && len(deletes) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("sqlite: begin tx: %w", err)
	}
	defer tx.Rollback()

	if len(upserts) > 0 {
		stmt, err := tx.Prepare(upsertSQL)
		if err != nil {
			return fmt.Errorf("sqlite: prepare upsert: %w", err)
		}
		defer stmt.Close()
		for _, p := range upserts {
			if _, err := stmt.Exec(
				p.ID, p.Host, p.Port, string(p.Protocol), string(p.State),
				p.HealthScore, p.LatencyMs, p.Country, string(p.Anonymity),
				p.ConsecutiveOK, p.ConsecutiveFail,
				p.FirstSeen.UTC().Format(time.RFC3339Nano),
				p.LastChecked.UTC().Format(time.RFC3339Nano),
				p.Source,
				optTime(p.LastSuccess), optTime(p.DiedAt), optTime(p.NextCheck),
			); err != nil {
				return fmt.Errorf("sqlite: upsert %s: %w", p.ID, err)
			}
		}
	}
	if len(deletes) > 0 {
		stmt, err := tx.Prepare(`DELETE FROM proxies WHERE id = ?`)
		if err != nil {
			return fmt.Errorf("sqlite: prepare delete: %w", err)
		}
		defer stmt.Close()
		for _, id := range deletes {
			if _, err := stmt.Exec(id); err != nil {
				return fmt.Errorf("sqlite: delete %s: %w", id, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit: %w", err)
	}
	return nil
}

// LoadAll reads every record.
func (s *sqliteStore) LoadAll() ([]*models.Proxy, error) {
	rows, err := s.db.Query(`SELECT id, host, port, protocol, state, health_score, latency_ms,
		country, anonymity, consecutive_ok, consecutive_fail, first_seen, last_checked, source,
		last_success, died_at, next_check
		FROM proxies`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query: %w", err)
	}
	defer rows.Close()

	var proxies []*models.Proxy
	for rows.Next() {
		p := &models.Proxy{}
		var (
			firstSeen, lastChecked, lastSuccess, diedAt, nextCheck string
			protocol, state                                        string
			country, anonymity                                     sql.NullString
		)
		if err := rows.Scan(
			&p.ID, &p.Host, &p.Port,
			&protocol, &state,
			&p.HealthScore, &p.LatencyMs,
			&country, &anonymity,
			&p.ConsecutiveOK, &p.ConsecutiveFail,
			&firstSeen, &lastChecked,
			&p.Source,
			&lastSuccess, &diedAt, &nextCheck,
		); err != nil {
			return nil, fmt.Errorf("sqlite: scan: %w", err)
		}
		p.Country = country.String
		p.Protocol = models.Protocol(protocol)
		p.State = models.ProxyState(state)
		p.Anonymity = models.Anonymity(anonymity.String)

		if p.FirstSeen, err = time.Parse(time.RFC3339Nano, firstSeen); err != nil {
			return nil, fmt.Errorf("sqlite: parse first_seen of %s: %w", p.ID, err)
		}
		if p.LastChecked, err = time.Parse(time.RFC3339Nano, lastChecked); err != nil {
			return nil, fmt.Errorf("sqlite: parse last_checked of %s: %w", p.ID, err)
		}
		if p.LastSuccess, err = parseOptTime(lastSuccess); err != nil {
			return nil, fmt.Errorf("sqlite: parse last_success of %s: %w", p.ID, err)
		}
		if p.DiedAt, err = parseOptTime(diedAt); err != nil {
			return nil, fmt.Errorf("sqlite: parse died_at of %s: %w", p.ID, err)
		}
		if p.NextCheck, err = parseOptTime(nextCheck); err != nil {
			return nil, fmt.Errorf("sqlite: parse next_check of %s: %w", p.ID, err)
		}
		proxies = append(proxies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows: %w", err)
	}
	return proxies, nil
}

// Close closes the database.
func (s *sqliteStore) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("sqlite: close: %w", err)
	}
	return nil
}

func optTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseOptTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}
