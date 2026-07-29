package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/google/uuid"
)

// UpsertStorageAccount creates or updates a storage account.
// On create, generates a random 64-byte account key (base64).
// Refuses the Azurite well-known account/key pair when listenAddr is non-loopback.
func (s *Store) UpsertStorageAccount(subID, rg, name, location, listenAddr string) (accountKey string, err error) {
	if location == "" {
		location = "eastus"
	}
	existing, ok, err := s.GetStorageAccountKey(name)
	if err != nil {
		return "", err
	}
	if ok {
		accountKey = existing
	} else {
		raw := make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return "", fmt.Errorf("generate account key: %w", err)
		}
		accountKey = base64.StdEncoding.EncodeToString(raw)
	}
	if config.AzuriteWellKnownCredentials(name, accountKey) && !config.ListenIsLoopback(listenAddr) {
		return "", fmt.Errorf("refusing Azurite well-known credentials on non-loopback listen %q", listenAddr)
	}
	sealed, err := Seal(s.master, []byte(accountKey))
	if err != nil {
		return "", fmt.Errorf("seal account key: %w", err)
	}
	_, err = s.db.Exec(`
INSERT INTO storage_accounts (subscription_id, resource_group, name, location, account_key_sealed)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(subscription_id, resource_group, name) DO UPDATE SET
  location=excluded.location,
  account_key_sealed=excluded.account_key_sealed`,
		subID, rg, name, location, sealed)
	if err != nil {
		return "", err
	}
	return accountKey, nil
}

// GetStorageAccount loads ARM metadata for a storage account.
func (s *Store) GetStorageAccount(subID, rg, name string) (location string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT location FROM storage_accounts
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, subID, rg, name).Scan(&location)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return location, true, nil
}

// GetStorageAccountKey unseals the account key for a storage account name.
func (s *Store) GetStorageAccountKey(accountName string) (string, bool, error) {
	var sealed []byte
	err := s.db.QueryRow(`SELECT account_key_sealed FROM storage_accounts WHERE name = ? LIMIT 1`, accountName).Scan(&sealed)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := Unseal(s.master, sealed)
	if err != nil {
		return "", false, fmt.Errorf("unseal account key: %w", err)
	}
	return string(plain), true, nil
}

// CreateContainer creates a blob container.
func (s *Store) CreateContainer(account, name string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO blob_containers (account, name) VALUES (?, ?)`, account, name)
	return err
}

// ListContainers returns container names for an account.
func (s *Store) ListContainers(account string) ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM blob_containers WHERE account = ? ORDER BY name`, account)
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

// DeleteContainer removes a container and its blobs.
func (s *Store) DeleteContainer(account, name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM blobs WHERE account = ? AND container = ?`, account, name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM blob_containers WHERE account = ? AND name = ?`, account, name); err != nil {
		return err
	}
	return tx.Commit()
}

// PutBlob stores blob content.
func (s *Store) PutBlob(account, container, name string, content []byte, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	_, err := s.db.Exec(`
INSERT INTO blobs (account, container, name, content, content_type)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(account, container, name) DO UPDATE SET
  content=excluded.content,
  content_type=excluded.content_type`,
		account, container, name, content, contentType)
	return err
}

// ListBlobs returns blob names in a container.
func (s *Store) ListBlobs(account, container string) ([]string, error) {
	rows, err := s.db.Query(`
SELECT name FROM blobs WHERE account = ? AND container = ? ORDER BY name`, account, container)
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

// GetBlob loads blob content.
func (s *Store) GetBlob(account, container, name string) (content []byte, contentType string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT content, content_type FROM blobs
WHERE account = ? AND container = ? AND name = ?`, account, container, name).
		Scan(&content, &contentType)
	if err == sql.ErrNoRows {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	return content, contentType, true, nil
}

// DeleteBlob removes one blob; ok is false when missing.
func (s *Store) DeleteBlob(account, container, name string) (ok bool, err error) {
	res, err := s.db.Exec(`
DELETE FROM blobs WHERE account = ? AND container = ? AND name = ?`, account, container, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CreateQueue creates a storage queue.
func (s *Store) CreateQueue(account, name string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO storage_queues (account, name) VALUES (?, ?)`, account, name)
	return err
}

// Enqueue appends a storage queue message.
func (s *Store) Enqueue(account, queue, body string) error {
	_, err := s.db.Exec(`
INSERT INTO storage_queue_messages (account, queue, body, inserted_at, visible_after)
VALUES (?, ?, ?, ?, '')`, account, queue, body, time.Now().UTC().Format(time.RFC3339))
	return err
}

// Peek returns the oldest visible queue message without removing it.
func (s *Store) Peek(account, queue string) (body string, ok bool, err error) {
	now := time.Now().UTC().Format(time.RFC3339)
	err = s.db.QueryRow(`
SELECT body FROM storage_queue_messages
WHERE account = ? AND queue = ?
  AND (visible_after = '' OR visible_after <= ?)
ORDER BY id ASC LIMIT 1`, account, queue, now).Scan(&body)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return body, true, nil
}

// Dequeue returns the oldest visible queue message.
// When visibilityTimeoutSec > 0, the message is hidden until now+timeout instead of deleted.
func (s *Store) Dequeue(account, queue string, visibilityTimeoutSec int) (body string, ok bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	var id int64
	err = tx.QueryRow(`
SELECT id, body FROM storage_queue_messages
WHERE account = ? AND queue = ?
  AND (visible_after = '' OR visible_after <= ?)
ORDER BY id ASC LIMIT 1`, account, queue, nowStr).Scan(&id, &body)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if visibilityTimeoutSec > 0 {
		vis := now.Add(time.Duration(visibilityTimeoutSec) * time.Second).Format(time.RFC3339)
		if _, err := tx.Exec(`UPDATE storage_queue_messages SET visible_after = ? WHERE id = ?`, vis, id); err != nil {
			return "", false, err
		}
	} else {
		if _, err := tx.Exec(`DELETE FROM storage_queue_messages WHERE id = ?`, id); err != nil {
			return "", false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return body, true, nil
}

// UpsertKeyVault creates or updates a Key Vault resource.
func (s *Store) UpsertKeyVault(subID, rg, name, location string) error {
	if location == "" {
		location = "eastus"
	}
	_, err := s.db.Exec(`
INSERT INTO keyvaults (subscription_id, resource_group, name, location)
VALUES (?, ?, ?, ?)
ON CONFLICT(subscription_id, resource_group, name) DO UPDATE SET location=excluded.location`,
		subID, rg, name, location)
	return err
}

// GetKeyVault loads Key Vault ARM metadata.
func (s *Store) GetKeyVault(subID, rg, name string) (location string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT location FROM keyvaults
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, subID, rg, name).Scan(&location)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return location, true, nil
}

// KeyVaultExists reports whether a vault name exists.
func (s *Store) KeyVaultExists(name string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM keyvaults WHERE name = ?`, name).Scan(&n)
	return n > 0, err
}

// PutSecret seals and stores a secret value (new version).
func (s *Store) PutSecret(vault, name, value string) (version string, err error) {
	version = uuid.NewString()
	sealed, err := Seal(s.master, []byte(value))
	if err != nil {
		return "", fmt.Errorf("seal secret: %w", err)
	}
	_, err = s.db.Exec(`
INSERT INTO keyvault_secrets (vault, name, value_sealed, version)
VALUES (?, ?, ?, ?)`, vault, name, sealed, version)
	if err != nil {
		return "", err
	}
	return version, nil
}

// GetSecret unseals the latest secret version.
func (s *Store) GetSecret(vault, name string) (value, version string, ok bool, err error) {
	var sealed []byte
	err = s.db.QueryRow(`
SELECT value_sealed, version FROM keyvault_secrets
WHERE vault = ? AND name = ?
ORDER BY rowid DESC LIMIT 1`, vault, name).Scan(&sealed, &version)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	plain, err := Unseal(s.master, sealed)
	if err != nil {
		return "", "", false, fmt.Errorf("unseal secret: %w", err)
	}
	return string(plain), version, true, nil
}

// PutKey seals and stores key material (new version).
func (s *Store) PutKey(vault, name string, keyMaterial []byte) (version string, err error) {
	version = uuid.NewString()
	sealed, err := Seal(s.master, keyMaterial)
	if err != nil {
		return "", fmt.Errorf("seal key: %w", err)
	}
	_, err = s.db.Exec(`
INSERT INTO keyvault_keys (vault, name, key_sealed, version)
VALUES (?, ?, ?, ?)`, vault, name, sealed, version)
	if err != nil {
		return "", err
	}
	return version, nil
}

// GetKey unseals the latest key material.
func (s *Store) GetKey(vault, name string) (keyMaterial []byte, version string, ok bool, err error) {
	var sealed []byte
	err = s.db.QueryRow(`
SELECT key_sealed, version FROM keyvault_keys
WHERE vault = ? AND name = ?
ORDER BY rowid DESC LIMIT 1`, vault, name).Scan(&sealed, &version)
	if err == sql.ErrNoRows {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	plain, err := Unseal(s.master, sealed)
	if err != nil {
		return nil, "", false, fmt.Errorf("unseal key: %w", err)
	}
	return plain, version, true, nil
}

// UpsertServiceBusNamespace creates or updates a Service Bus namespace with a sealed SAS key.
func (s *Store) UpsertServiceBusNamespace(subID, rg, name, location string) (sasKey string, err error) {
	if location == "" {
		location = "eastus"
	}
	existing, ok, err := s.GetSBNamespaceKey(name)
	if err != nil {
		return "", err
	}
	if ok {
		sasKey = existing
	} else {
		raw := make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return "", fmt.Errorf("generate sas key: %w", err)
		}
		sasKey = base64.StdEncoding.EncodeToString(raw)
	}
	sealed, err := Seal(s.master, []byte(sasKey))
	if err != nil {
		return "", fmt.Errorf("seal sas key: %w", err)
	}
	_, err = s.db.Exec(`
INSERT INTO servicebus_namespaces (subscription_id, resource_group, name, location, sas_key_sealed)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(subscription_id, resource_group, name) DO UPDATE SET
  location=excluded.location,
  sas_key_sealed=excluded.sas_key_sealed`,
		subID, rg, name, location, sealed)
	if err != nil {
		return "", err
	}
	return sasKey, nil
}

// GetServiceBusNamespace loads ARM metadata for a namespace.
func (s *Store) GetServiceBusNamespace(subID, rg, name string) (location string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT location FROM servicebus_namespaces
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, subID, rg, name).Scan(&location)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return location, true, nil
}

// GetSBNamespaceKey unseals the namespace SAS key.
func (s *Store) GetSBNamespaceKey(namespace string) (string, bool, error) {
	var sealed []byte
	err := s.db.QueryRow(`SELECT sas_key_sealed FROM servicebus_namespaces WHERE name = ? LIMIT 1`, namespace).Scan(&sealed)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := Unseal(s.master, sealed)
	if err != nil {
		return "", false, fmt.Errorf("unseal sas key: %w", err)
	}
	return string(plain), true, nil
}

// CreateServiceBusQueue creates a Service Bus queue.
func (s *Store) CreateServiceBusQueue(namespace, name string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO servicebus_queues (namespace, name) VALUES (?, ?)`, namespace, name)
	return err
}

// EnqueueSB appends a Service Bus message.
func (s *Store) EnqueueSB(namespace, queue string, body []byte) error {
	_, err := s.db.Exec(`
INSERT INTO servicebus_messages (namespace, queue, body, locked_until, inserted_at)
VALUES (?, ?, ?, '', ?)`, namespace, queue, body, time.Now().UTC().Format(time.RFC3339))
	return err
}

// DequeueSB removes and returns the oldest Service Bus message.
func (s *Store) DequeueSB(namespace, queue string) (body []byte, ok bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	err = tx.QueryRow(`
SELECT id, body FROM servicebus_messages
WHERE namespace = ? AND queue = ?
ORDER BY id ASC LIMIT 1`, namespace, queue).Scan(&id, &body)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(`DELETE FROM servicebus_messages WHERE id = ?`, id); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return body, true, nil
}
