package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/tatlilimon/proxier/internal/models"

	_ "modernc.org/sqlite"
)

type sqliteStore struct {
	db *sql.DB

	saveStmt   *sql.Stmt
	loadStmt   *sql.Stmt
	deleteStmt *sql.Stmt
}

func NewSQLiteStore(path string) (Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS proxies (
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
		db.Close()
		return nil, fmt.Errorf("sqlite: migrate: %w", err)
	}

	s := &sqliteStore{db: db}

	s.saveStmt, err = db.Prepare(`INSERT OR REPLACE INTO proxies
		(id, host, port, protocol, state, health_score, latency_ms, country, anonymity,
		 consecutive_ok, consecutive_fail, first_seen, last_checked, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: prepare save: %w", err)
	}

	s.loadStmt, err = db.Prepare(`SELECT id, host, port, protocol, state, health_score, latency_ms,
		country, anonymity, consecutive_ok, consecutive_fail, first_seen, last_checked, source
		FROM proxies`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: prepare load: %w", err)
	}

	s.deleteStmt, err = db.Prepare(`DELETE FROM proxies WHERE id = ?`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: prepare delete: %w", err)
	}

	return s, nil
}

func (s *sqliteStore) Save(p *models.Proxy) error {
	_, err := s.saveStmt.Exec(
		p.ID,
		p.Host,
		p.Port,
		string(p.Protocol),
		string(p.State),
		p.HealthScore,
		p.LatencyMs,
		p.Country,
		string(p.Anonymity),
		p.ConsecutiveOK,
		p.ConsecutiveFail,
		p.FirstSeen.Format(time.RFC3339),
		p.LastChecked.Format(time.RFC3339),
		p.Source,
	)
	if err != nil {
		return fmt.Errorf("sqlite: save: %w", err)
	}
	return nil
}

func (s *sqliteStore) SaveBatch(proxies []*models.Proxy) error {
	if len(proxies) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("sqlite: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO proxies
		(id, host, port, protocol, state, health_score, latency_ms, country, anonymity,
		 consecutive_ok, consecutive_fail, first_seen, last_checked, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare batch: %w", err)
	}
	defer stmt.Close()

	for _, p := range proxies {
		_, err := stmt.Exec(
			p.ID,
			p.Host,
			p.Port,
			string(p.Protocol),
			string(p.State),
			p.HealthScore,
			p.LatencyMs,
			p.Country,
			string(p.Anonymity),
			p.ConsecutiveOK,
			p.ConsecutiveFail,
			p.FirstSeen.Format(time.RFC3339),
			p.LastChecked.Format(time.RFC3339),
			p.Source,
		)
		if err != nil {
			return fmt.Errorf("sqlite: batch exec: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit batch: %w", err)
	}
	return nil
}

func (s *sqliteStore) LoadAll() ([]*models.Proxy, error) {
	rows, err := s.loadStmt.Query()
	if err != nil {
		return nil, fmt.Errorf("sqlite: query: %w", err)
	}
	defer rows.Close()

	var proxies []*models.Proxy
	for rows.Next() {
		p := &models.Proxy{}
		var firstSeen, lastChecked string
		var protocol, state, anonymity string

		err := rows.Scan(
			&p.ID, &p.Host, &p.Port,
			&protocol, &state,
			&p.HealthScore, &p.LatencyMs,
			&p.Country, &anonymity,
			&p.ConsecutiveOK, &p.ConsecutiveFail,
			&firstSeen, &lastChecked,
			&p.Source,
		)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan: %w", err)
		}

		p.Protocol = models.Protocol(protocol)
		p.State = models.ProxyState(state)
		p.Anonymity = models.Anonymity(anonymity)

		p.FirstSeen, err = time.Parse(time.RFC3339, firstSeen)
		if err != nil {
			return nil, fmt.Errorf("sqlite: parse first_seen: %w", err)
		}
		p.LastChecked, err = time.Parse(time.RFC3339, lastChecked)
		if err != nil {
			return nil, fmt.Errorf("sqlite: parse last_checked: %w", err)
		}

		proxies = append(proxies, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows: %w", err)
	}

	return proxies, nil
}

func (s *sqliteStore) Delete(id string) error {
	_, err := s.deleteStmt.Exec(id)
	if err != nil {
		return fmt.Errorf("sqlite: delete: %w", err)
	}
	return nil
}

func (s *sqliteStore) Close() error {
	var errs []error

	if s.saveStmt != nil {
		if err := s.saveStmt.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close save stmt: %w", err))
		}
	}
	if s.loadStmt != nil {
		if err := s.loadStmt.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close load stmt: %w", err))
		}
	}
	if s.deleteStmt != nil {
		if err := s.deleteStmt.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close delete stmt: %w", err))
		}
	}
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close db: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sqlite: close: %v", errs)
	}
	return nil
}
