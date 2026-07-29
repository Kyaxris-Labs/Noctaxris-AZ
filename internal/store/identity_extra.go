package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/google/uuid"
)

// EnsureEntraSigningKey loads or creates a sealed RSA private key for lab JWTs.
func (s *Store) EnsureEntraSigningKey() (kid string, priv *rsa.PrivateKey, err error) {
	var sealed []byte
	err = s.db.QueryRow(`SELECT kid, private_key_sealed FROM entra_signing_keys ORDER BY created_at ASC LIMIT 1`).
		Scan(&kid, &sealed)
	if err == nil {
		plain, uerr := Unseal(s.master, sealed)
		if uerr != nil {
			return "", nil, fmt.Errorf("unseal entra signing key: %w", uerr)
		}
		block, _ := pem.Decode(plain)
		if block == nil {
			return "", nil, fmt.Errorf("unseal entra signing key: invalid PEM")
		}
		key, perr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if perr != nil {
			parsed, aerr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if aerr != nil {
				return "", nil, fmt.Errorf("parse entra signing key: %w", perr)
			}
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				return "", nil, fmt.Errorf("entra signing key is not RSA")
			}
		}
		return kid, key, nil
	}
	if err != sql.ErrNoRows {
		return "", nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("generate entra signing key: %w", err)
	}
	kid = uuid.NewString()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	sealed, err = Seal(s.master, pemBytes)
	if err != nil {
		return "", nil, fmt.Errorf("seal entra signing key: %w", err)
	}
	_, err = s.db.Exec(`
INSERT INTO entra_signing_keys (kid, private_key_sealed, created_at)
VALUES (?, ?, ?)`, kid, sealed, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return "", nil, err
	}
	return kid, key, nil
}

// UpsertManagedIdentity creates or updates a user-assigned managed identity.
func (s *Store) UpsertManagedIdentity(subID, rg, name, location, principalID, clientID string) error {
	if location == "" {
		location = "eastus"
	}
	_, err := s.db.Exec(`
INSERT INTO managed_identities (subscription_id, resource_group, name, location, principal_id, client_id)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(subscription_id, resource_group, name) DO UPDATE SET
  location=excluded.location,
  principal_id=excluded.principal_id,
  client_id=excluded.client_id`,
		subID, rg, name, location, principalID, clientID)
	return err
}

// GetManagedIdentity loads one identity.
func (s *Store) GetManagedIdentity(subID, rg, name string) (location, principalID, clientID string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT location, principal_id, client_id FROM managed_identities
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, subID, rg, name).
		Scan(&location, &principalID, &clientID)
	if err == sql.ErrNoRows {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return location, principalID, clientID, true, nil
}

// DeleteManagedIdentity removes one identity.
func (s *Store) DeleteManagedIdentity(subID, rg, name string) (ok bool, err error) {
	res, err := s.db.Exec(`
DELETE FROM managed_identities WHERE subscription_id = ? AND resource_group = ? AND name = ?`, subID, rg, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListManagedIdentities lists identities in a resource group.
func (s *Store) ListManagedIdentities(subID, rg string) ([]struct {
	Name, Location, PrincipalID, ClientID string
}, error) {
	rows, err := s.db.Query(`
SELECT name, location, principal_id, client_id FROM managed_identities
WHERE subscription_id = ? AND resource_group = ? ORDER BY name`, subID, rg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		Name, Location, PrincipalID, ClientID string
	}
	for rows.Next() {
		var row struct {
			Name, Location, PrincipalID, ClientID string
		}
		if err := rows.Scan(&row.Name, &row.Location, &row.PrincipalID, &row.ClientID); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// FindManagedIdentityByClientID resolves a client id to principal metadata.
func (s *Store) FindManagedIdentityByClientID(clientID string) (principalID, name string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT principal_id, name FROM managed_identities WHERE client_id = ? LIMIT 1`, clientID).
		Scan(&principalID, &name)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return principalID, name, true, nil
}

// FindManagedIdentityByPrincipalID resolves a principal/object id to client metadata.
func (s *Store) FindManagedIdentityByPrincipalID(principalID string) (clientID, name string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT client_id, name FROM managed_identities WHERE principal_id = ? LIMIT 1`, principalID).
		Scan(&clientID, &name)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return clientID, name, true, nil
}

// ListRoleAssignmentsByScopePrefix returns assignments whose scope equals or is under prefix.
func (s *Store) ListRoleAssignmentsByScopePrefix(prefix string) ([]authz.Assignment, error) {
	rows, err := s.db.Query(`
SELECT id, scope, role_definition_id, principal_id, principal_type FROM role_assignments
WHERE scope = ? OR scope LIKE ? || '/%'
ORDER BY id`, prefix, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authz.Assignment
	for rows.Next() {
		var a authz.Assignment
		if err := rows.Scan(&a.ID, &a.Scope, &a.RoleDefinitionID, &a.PrincipalID, &a.PrincipalType); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SoftDeleteSecret moves the latest secret version into deleted storage (immediate lab theatre).
func (s *Store) SoftDeleteSecret(vault, name string) (ok bool, err error) {
	value, version, found, err := s.GetSecret(vault, name)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	sealed, err := Seal(s.master, []byte(value))
	if err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
INSERT INTO keyvault_deleted_secrets (vault, name, value_sealed, version, deleted_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(vault, name, version) DO UPDATE SET value_sealed=excluded.value_sealed, deleted_at=excluded.deleted_at`,
		vault, name, sealed, version, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM keyvault_secrets WHERE vault = ? AND name = ?`, vault, name); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// RecoverSecret restores the latest deleted secret version.
func (s *Store) RecoverSecret(vault, name string) (version string, ok bool, err error) {
	var sealed []byte
	err = s.db.QueryRow(`
SELECT value_sealed, version FROM keyvault_deleted_secrets
WHERE vault = ? AND name = ?
ORDER BY deleted_at DESC LIMIT 1`, vault, name).Scan(&sealed, &version)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := Unseal(s.master, sealed)
	if err != nil {
		return "", false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
INSERT INTO keyvault_secrets (vault, name, value_sealed, version)
VALUES (?, ?, ?, ?)`, vault, name, sealed, version); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(`DELETE FROM keyvault_deleted_secrets WHERE vault = ? AND name = ? AND version = ?`, vault, name, version); err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	_ = plain
	return version, true, nil
}
