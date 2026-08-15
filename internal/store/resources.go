package store

import (
	"database/sql"
)

// ProviderResource is a generic ARM control-plane row for lab resources.
type ProviderResource struct {
	Provider       string
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Location       string
	PropertiesJSON string
}

// UpsertProviderResource creates or updates a provider ARM resource.
func (s *Store) UpsertProviderResource(provider, sub, rg, name, location, propsJSON string) error {
	if location == "" {
		location = "eastus"
	}
	if propsJSON == "" {
		propsJSON = "{}"
	}
	_, err := s.db.Exec(`
INSERT INTO arm_lab_resources (provider, subscription_id, resource_group, name, location, properties_json)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(provider, subscription_id, resource_group, name) DO UPDATE SET
  location=excluded.location, properties_json=excluded.properties_json`,
		provider, sub, rg, name, location, propsJSON)
	return err
}

// GetProviderResource loads one provider ARM resource.
func (s *Store) GetProviderResource(provider, sub, rg, name string) (ProviderResource, bool, error) {
	var row ProviderResource
	err := s.db.QueryRow(`
SELECT provider, subscription_id, resource_group, name, location, properties_json
FROM arm_lab_resources
WHERE provider = ? AND subscription_id = ? AND resource_group = ? AND name = ?`,
		provider, sub, rg, name).
		Scan(&row.Provider, &row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location, &row.PropertiesJSON)
	if err == sql.ErrNoRows {
		return ProviderResource{}, false, nil
	}
	if err != nil {
		return ProviderResource{}, false, err
	}
	return row, true, nil
}

// ListProviderResources lists resources of a provider in a resource group.
func (s *Store) ListProviderResources(provider, sub, rg string) ([]ProviderResource, error) {
	rows, err := s.db.Query(`
SELECT provider, subscription_id, resource_group, name, location, properties_json
FROM arm_lab_resources
WHERE provider = ? AND subscription_id = ? AND resource_group = ?
ORDER BY name`, provider, sub, rg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProviderResource
	for rows.Next() {
		var row ProviderResource
		if err := rows.Scan(&row.Provider, &row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location, &row.PropertiesJSON); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// DeleteProviderResource deletes a provider ARM resource.
func (s *Store) DeleteProviderResource(provider, sub, rg, name string) error {
	res, err := s.db.Exec(`
DELETE FROM arm_lab_resources
WHERE provider = ? AND subscription_id = ? AND resource_group = ? AND name = ?`,
		provider, sub, rg, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetProviderResourceByName finds a resource by provider and name.
func (s *Store) GetProviderResourceByName(provider, name string) (ProviderResource, bool, error) {
	var row ProviderResource
	err := s.db.QueryRow(`
SELECT provider, subscription_id, resource_group, name, location, properties_json
FROM arm_lab_resources WHERE provider = ? AND name = ? LIMIT 1`, provider, name).
		Scan(&row.Provider, &row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location, &row.PropertiesJSON)
	if err == sql.ErrNoRows {
		return ProviderResource{}, false, nil
	}
	if err != nil {
		return ProviderResource{}, false, err
	}
	return row, true, nil
}
