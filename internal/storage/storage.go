package storage

import (
	"fmt"
	"strings"

	"github.com/tatlilimon/proxier/internal/models"
)

// Store defines the persistence interface for proxy records.
type Store interface {
	// Apply writes upserts and deletes in one transaction. On error nothing
	// is written, and the caller keeps the changes for the next attempt.
	Apply(upserts []*models.Proxy, deletes []string) error
	LoadAll() ([]*models.Proxy, error)
	Close() error
}

// New creates a Store backend. Only "sqlite" (the default) is implemented.
func New(backend, path string) (Store, error) {
	switch strings.ToLower(backend) {
	case "", "sqlite":
		return NewSQLiteStore(path)
	default:
		return nil, fmt.Errorf("unknown storage backend %q (only \"sqlite\" is supported)", backend)
	}
}
