package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
)

// UpsertCosmosAccount creates a Cosmos account with a sealed key.
func (s *Store) UpsertCosmosAccount(sub, rg, name, location string) (primaryKey string, err error) {
	if location == "" {
		location = "eastus"
	}
	var sealed []byte
	err = s.db.QueryRow(`
SELECT key_sealed FROM cosmos_accounts
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, sub, rg, name).Scan(&sealed)
	if err == nil {
		raw, uerr := Unseal(s.master, sealed)
		if uerr != nil {
			return "", uerr
		}
		_, err = s.db.Exec(`
UPDATE cosmos_accounts SET location = ? WHERE subscription_id = ? AND resource_group = ? AND name = ?`,
			location, sub, rg, name)
		return string(raw), err
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}
	primaryKey = base64.StdEncoding.EncodeToString(keyBytes)
	sealed, err = Seal(s.master, []byte(primaryKey))
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`
INSERT INTO cosmos_accounts (subscription_id, resource_group, name, location, key_sealed)
VALUES (?, ?, ?, ?, ?)`, sub, rg, name, location, sealed)
	return primaryKey, err
}

// GetCosmosAccount loads account location and unsealed key.
func (s *Store) GetCosmosAccount(sub, rg, name string) (location, key string, ok bool, err error) {
	var sealed []byte
	err = s.db.QueryRow(`
SELECT location, key_sealed FROM cosmos_accounts
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, sub, rg, name).Scan(&location, &sealed)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	raw, err := Unseal(s.master, sealed)
	if err != nil {
		return "", "", false, err
	}
	return location, string(raw), true, nil
}

// GetCosmosAccountByName loads by account name.
func (s *Store) GetCosmosAccountByName(name string) (sub, rg, location, key string, ok bool, err error) {
	var sealed []byte
	err = s.db.QueryRow(`
SELECT subscription_id, resource_group, location, key_sealed FROM cosmos_accounts WHERE name = ? LIMIT 1`, name).
		Scan(&sub, &rg, &location, &sealed)
	if err == sql.ErrNoRows {
		return "", "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", "", false, err
	}
	raw, err := Unseal(s.master, sealed)
	if err != nil {
		return "", "", "", "", false, err
	}
	return sub, rg, location, string(raw), true, nil
}

// CreateCosmosDatabase creates a database.
func (s *Store) CreateCosmosDatabase(account, name string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO cosmos_databases (account, name) VALUES (?, ?)`, account, name)
	return err
}

// CreateCosmosContainer creates a container.
func (s *Store) CreateCosmosContainer(account, database, name, partitionKey string) error {
	if partitionKey == "" {
		partitionKey = "/id"
	}
	_, err := s.db.Exec(`
INSERT INTO cosmos_containers (account, database_name, name, partition_key)
VALUES (?, ?, ?, ?)
ON CONFLICT(account, database_name, name) DO UPDATE SET partition_key=excluded.partition_key`,
		account, database, name, partitionKey)
	return err
}

// UpsertCosmosItem upserts an item.
func (s *Store) UpsertCosmosItem(account, database, container, id, pk, bodyJSON string) error {
	_, err := s.db.Exec(`
INSERT INTO cosmos_items (account, database_name, container, id, partition_key_value, body_json)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(account, database_name, container, id, partition_key_value) DO UPDATE SET body_json=excluded.body_json`,
		account, database, container, id, pk, bodyJSON)
	return err
}

// GetCosmosItem point-reads an item.
func (s *Store) GetCosmosItem(account, database, container, id, pk string) (string, bool, error) {
	var body string
	err := s.db.QueryRow(`
SELECT body_json FROM cosmos_items
WHERE account = ? AND database_name = ? AND container = ? AND id = ? AND partition_key_value = ?`,
		account, database, container, id, pk).Scan(&body)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return body, true, nil
}

// QueryCosmosItemsByID equality query on id.
func (s *Store) QueryCosmosItemsByID(account, database, container, id string) ([]string, error) {
	rows, err := s.db.Query(`
SELECT body_json FROM cosmos_items
WHERE account = ? AND database_name = ? AND container = ? AND id = ?`,
		account, database, container, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		out = append(out, body)
	}
	return out, rows.Err()
}
