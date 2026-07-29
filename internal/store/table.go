package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// TableEntity is a Table Storage entity row.
type TableEntity struct {
	PartitionKey string
	RowKey       string
	ETag         string
	Properties   map[string]any
}

// CreateTable creates a table in an account.
func (s *Store) CreateTable(account, name string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO tables (account, table_name) VALUES (?, ?)`, account, name)
	return err
}

// DeleteTable removes a table and all of its entities.
func (s *Store) DeleteTable(account, name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM table_entities WHERE account = ? AND table_name = ?`, account, name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM tables WHERE account = ? AND table_name = ?`, account, name); err != nil {
		return err
	}
	return tx.Commit()
}

// ListTables returns table names for an account.
func (s *Store) ListTables(account string) ([]string, error) {
	rows, err := s.db.Query(`SELECT table_name FROM tables WHERE account = ? ORDER BY table_name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// UpsertEntity inserts or updates an entity. When merge is true, existing
// properties are retained unless overwritten by props.
func (s *Store) UpsertEntity(account, table, pk, rk string, props map[string]any, merge bool) (etag string, err error) {
	if props == nil {
		props = map[string]any{}
	}
	existing, ok, err := s.GetEntity(account, table, pk, rk)
	if err != nil {
		return "", err
	}
	merged := map[string]any{}
	if merge && ok {
		for k, v := range existing.Properties {
			merged[k] = v
		}
	}
	for k, v := range props {
		if k == "PartitionKey" || k == "RowKey" || k == "Timestamp" || strings.HasPrefix(k, "odata.") {
			continue
		}
		merged[k] = v
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return "", fmt.Errorf("marshal properties: %w", err)
	}
	etag = `W/"` + uuid.NewString() + `"`
	_, err = s.db.Exec(`
INSERT INTO table_entities (account, table_name, partition_key, row_key, etag, properties_json)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(account, table_name, partition_key, row_key) DO UPDATE SET
  etag=excluded.etag,
  properties_json=excluded.properties_json`,
		account, table, pk, rk, etag, string(raw))
	return etag, err
}

// InsertEntity inserts a new entity; returns false when the key already exists.
func (s *Store) InsertEntity(account, table, pk, rk string, props map[string]any) (etag string, created bool, err error) {
	_, ok, err := s.GetEntity(account, table, pk, rk)
	if err != nil {
		return "", false, err
	}
	if ok {
		return "", false, nil
	}
	etag, err = s.UpsertEntity(account, table, pk, rk, props, false)
	if err != nil {
		return "", false, err
	}
	return etag, true, nil
}

// GetEntity loads one entity by partition and row key.
func (s *Store) GetEntity(account, table, pk, rk string) (TableEntity, bool, error) {
	var etag, propsJSON string
	err := s.db.QueryRow(`
SELECT etag, properties_json FROM table_entities
WHERE account = ? AND table_name = ? AND partition_key = ? AND row_key = ?`,
		account, table, pk, rk).Scan(&etag, &propsJSON)
	if err == sql.ErrNoRows {
		return TableEntity{}, false, nil
	}
	if err != nil {
		return TableEntity{}, false, err
	}
	props := map[string]any{}
	if propsJSON != "" {
		if err := json.Unmarshal([]byte(propsJSON), &props); err != nil {
			return TableEntity{}, false, fmt.Errorf("unmarshal properties: %w", err)
		}
	}
	return TableEntity{
		PartitionKey: pk,
		RowKey:       rk,
		ETag:         etag,
		Properties:   props,
	}, true, nil
}

// DeleteEntity removes one entity; ok is false when missing.
func (s *Store) DeleteEntity(account, table, pk, rk string) (ok bool, err error) {
	res, err := s.db.Exec(`
DELETE FROM table_entities
WHERE account = ? AND table_name = ? AND partition_key = ? AND row_key = ?`,
		account, table, pk, rk)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// QueryEntities returns entities with optional PartitionKey/RowKey equality and $top.
// propEq filters additional string properties with exact equality (lite).
func (s *Store) QueryEntities(account, table, filterPK, filterRK string, propEq map[string]string, top int) ([]TableEntity, error) {
	q := `SELECT partition_key, row_key, etag, properties_json FROM table_entities WHERE account = ? AND table_name = ?`
	args := []any{account, table}
	if filterPK != "" {
		q += ` AND partition_key = ?`
		args = append(args, filterPK)
	}
	if filterRK != "" {
		q += ` AND row_key = ?`
		args = append(args, filterRK)
	}
	q += ` ORDER BY partition_key, row_key`
	// Apply SQL LIMIT only when no in-memory property filter (propEq runs after scan).
	if top > 0 && len(propEq) == 0 {
		q += ` LIMIT ?`
		args = append(args, top)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TableEntity
	for rows.Next() {
		var pk, rk, etag, propsJSON string
		if err := rows.Scan(&pk, &rk, &etag, &propsJSON); err != nil {
			return nil, err
		}
		props := map[string]any{}
		if propsJSON != "" {
			if err := json.Unmarshal([]byte(propsJSON), &props); err != nil {
				return nil, fmt.Errorf("unmarshal properties: %w", err)
			}
		}
		if !matchPropEq(props, propEq) {
			continue
		}
		out = append(out, TableEntity{
			PartitionKey: pk,
			RowKey:       rk,
			ETag:         etag,
			Properties:   props,
		})
		if top > 0 && len(propEq) > 0 && len(out) >= top {
			break
		}
	}
	return out, rows.Err()
}

func matchPropEq(props map[string]any, propEq map[string]string) bool {
	for k, want := range propEq {
		v, ok := props[k]
		if !ok {
			return false
		}
		if fmt.Sprint(v) != want {
			return false
		}
	}
	return true
}
