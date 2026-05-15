package storage

import (
	"fmt"
	"strings"

	"github.com/tatlilimon/proxier/internal/models"
)

// Store defines the persistence interface for proxy records.
type Store interface {
	Save(p *models.Proxy) error
	LoadAll() ([]*models.Proxy, error)
	Delete(id string) error
	Close() error
}

// New creates a Store backend based on the provided name and path.
// Supported backends: "sqlite" (default if empty).
func New(backend, path string) (Store, error) {
	switch strings.ToLower(backend) {
	case "", "sqlite":
		return NewSQLiteStore(path)
	case "json":
		return nil, fmt.Errorf("json backend not implemented yet")
	default:
		return nil, fmt.Errorf("unknown storage backend: %q", backend)
	}
}
