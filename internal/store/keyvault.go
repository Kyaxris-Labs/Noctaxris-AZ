package store

import (
	"database/sql"

	"github.com/google/uuid"
)

// PutKeyVaultCertificate seals and stores a certificate PEM.
func (s *Store) PutKeyVaultCertificate(vault, name, version string, pem []byte, policyJSON string) error {
	if version == "" {
		version = uuid.NewString()
	}
	if policyJSON == "" {
		policyJSON = "{}"
	}
	sealed, err := Seal(s.master, pem)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO keyvault_certificates (vault, name, version, cert_pem_sealed, policy_json)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(vault, name, version) DO UPDATE SET cert_pem_sealed=excluded.cert_pem_sealed, policy_json=excluded.policy_json`,
		vault, name, version, sealed, policyJSON)
	return err
}

// GetKeyVaultCertificate returns the latest certificate version.
func (s *Store) GetKeyVaultCertificate(vault, name string) (version string, pem []byte, policyJSON string, ok bool, err error) {
	var sealed []byte
	err = s.db.QueryRow(`
SELECT version, cert_pem_sealed, policy_json FROM keyvault_certificates
WHERE vault = ? AND name = ? ORDER BY version DESC LIMIT 1`, vault, name).
		Scan(&version, &sealed, &policyJSON)
	if err == sql.ErrNoRows {
		return "", nil, "", false, nil
	}
	if err != nil {
		return "", nil, "", false, err
	}
	pem, err = Unseal(s.master, sealed)
	if err != nil {
		return "", nil, "", false, err
	}
	return version, pem, policyJSON, true, nil
}
