package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed lab state store.
type Store struct {
	db       *sql.DB
	master   MasterKey
	dataRoot string
}

// Open opens or creates state.db under dataRoot and runs migrations.
func Open(dataRoot string, master MasterKey) (*Store, error) {
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create data root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dataRoot, "blobs"), 0o700); err != nil {
		return nil, fmt.Errorf("create blobs root: %w", err)
	}
	dbPath := filepath.Join(dataRoot, "state.db")
	dsn := "file:" + filepath.ToSlash(dbPath) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, master: master, dataRoot: dataRoot}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM schema_version`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, schemaVersion); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Master returns the master key.
func (s *Store) Master() MasterKey { return s.master }

// DataRoot returns the data root path.
func (s *Store) DataRoot() string { return s.dataRoot }

// EnsureRoot seeds tenant subscription and records the root principal.
func (s *Store) EnsureRoot(tenantID, subscriptionID, rootPrincipal string) error {
	_, err := s.db.Exec(`
INSERT INTO subscriptions (id, display_name, state, tenant_id)
VALUES (?, ?, 'Enabled', ?)
ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, tenant_id=excluded.tenant_id`,
		subscriptionID, "Noctaxris-AZ Lab", tenantID)
	if err != nil {
		return fmt.Errorf("seed subscription: %w", err)
	}
	_ = rootPrincipal
	return nil
}

// LookupAccessToken resolves a token hash to a principal id.
func (s *Store) LookupAccessToken(tokenHash string, now time.Time) (principalID string, ok bool, err error) {
	var expires string
	err = s.db.QueryRow(`SELECT principal_id, expires_at FROM access_tokens WHERE token_hash = ?`, tokenHash).
		Scan(&principalID, &expires)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if expires != "" {
		t, perr := time.Parse(time.RFC3339, expires)
		if perr == nil && now.After(t) {
			return "", false, nil
		}
	}
	return principalID, true, nil
}

// PutAccessToken stores a hashed access token for a principal.
func (s *Store) PutAccessToken(tokenHash, principalID string, expiresAt time.Time) error {
	exp := ""
	if !expiresAt.IsZero() {
		exp = expiresAt.UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(`
INSERT INTO access_tokens (token_hash, principal_id, expires_at, created_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(token_hash) DO UPDATE SET principal_id=excluded.principal_id, expires_at=excluded.expires_at`,
		tokenHash, principalID, exp, time.Now().UTC().Format(time.RFC3339))
	return err
}

// DB exposes the underlying database for service packages in the same module.
func (s *Store) DB() *sql.DB { return s.db }
