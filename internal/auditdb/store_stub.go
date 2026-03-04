//go:build !vibeguard_full

package auditdb

import "time"

// Store is a placeholder implementation for the lite build: SQLite audit persistence is not available.
type Store struct{}

func Open(_ string) (*Store, error) { return nil, ErrNotAvailable }

func (s *Store) Add(ev AuditEvent) (AuditEvent, error) { return ev, ErrNotAvailable }

func (s *Store) Update(_ int64, _ func(*AuditEvent)) error { return ErrNotAvailable }

func (s *Store) List(_ int) ([]AuditEvent, error) { return nil, ErrNotAvailable }

func (s *Store) MaxID() (int64, error) { return 0, ErrNotAvailable }

func (s *Store) Purge(_ time.Duration) (int64, error) { return 0, ErrNotAvailable }

func (s *Store) Clear() error { return ErrNotAvailable }

func (s *Store) Close() error { return nil }

func (s *Store) StartPurgeLoop(_ time.Duration, _ time.Duration) func() { return func() {} }
