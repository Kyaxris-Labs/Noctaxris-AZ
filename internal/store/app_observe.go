package store

import (
	"database/sql"
	"fmt"
	"time"
)

// AppConfigStore is an App Configuration store row.
type AppConfigStore struct {
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Location       string
}

// AppConfigKV is a key-value entry in an App Configuration store.
type AppConfigKV struct {
	Store string
	Key   string
	Label string
	Value string
}

// FunctionApp is a Function App control-plane row with mock invoke response.
type FunctionApp struct {
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Location       string
	MockResponse   string
}

// UpsertAppConfig creates or updates an App Configuration store.
func (s *Store) UpsertAppConfig(subID, rg, name, location string) error {
	if location == "" {
		location = "eastus"
	}
	_, err := s.db.Exec(`
INSERT INTO appconfig_stores (subscription_id, resource_group, name, location)
VALUES (?, ?, ?, ?)
ON CONFLICT(subscription_id, resource_group, name) DO UPDATE SET location=excluded.location`,
		subID, rg, name, location)
	return err
}

// GetAppConfig loads one App Configuration store.
func (s *Store) GetAppConfig(subID, rg, name string) (AppConfigStore, bool, error) {
	var row AppConfigStore
	err := s.db.QueryRow(`
SELECT subscription_id, resource_group, name, location FROM appconfig_stores
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, subID, rg, name).
		Scan(&row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location)
	if err == sql.ErrNoRows {
		return AppConfigStore{}, false, nil
	}
	if err != nil {
		return AppConfigStore{}, false, err
	}
	return row, true, nil
}

// GetAppConfigByName loads a store by name (any subscription/RG).
func (s *Store) GetAppConfigByName(name string) (AppConfigStore, bool, error) {
	var row AppConfigStore
	err := s.db.QueryRow(`
SELECT subscription_id, resource_group, name, location FROM appconfig_stores WHERE name = ? LIMIT 1`, name).
		Scan(&row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location)
	if err == sql.ErrNoRows {
		return AppConfigStore{}, false, nil
	}
	if err != nil {
		return AppConfigStore{}, false, err
	}
	return row, true, nil
}

// ListAppConfigs lists stores in a resource group.
func (s *Store) ListAppConfigs(subID, rg string) ([]AppConfigStore, error) {
	rows, err := s.db.Query(`
SELECT subscription_id, resource_group, name, location FROM appconfig_stores
WHERE subscription_id = ? AND resource_group = ? ORDER BY name`, subID, rg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppConfigStore
	for rows.Next() {
		var row AppConfigStore
		if err := rows.Scan(&row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// DeleteAppConfig removes a store and its key-values.
func (s *Store) DeleteAppConfig(subID, rg, name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM appconfig_kvs WHERE store = ?`, name); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM appconfig_stores WHERE subscription_id = ? AND resource_group = ? AND name = ?`,
		subID, rg, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// SetAppConfigKV upserts a key-value (empty label when omitted).
func (s *Store) SetAppConfigKV(storeName, key, label, value string) error {
	if storeName == "" || key == "" {
		return fmt.Errorf("store and key are required")
	}
	_, err := s.db.Exec(`
INSERT INTO appconfig_kvs (store, key, label, value) VALUES (?, ?, ?, ?)
ON CONFLICT(store, key, label) DO UPDATE SET value=excluded.value`,
		storeName, key, label, value)
	return err
}

// GetAppConfigKV loads one key-value.
func (s *Store) GetAppConfigKV(storeName, key, label string) (AppConfigKV, bool, error) {
	var row AppConfigKV
	err := s.db.QueryRow(`
SELECT store, key, label, value FROM appconfig_kvs WHERE store = ? AND key = ? AND label = ?`,
		storeName, key, label).
		Scan(&row.Store, &row.Key, &row.Label, &row.Value)
	if err == sql.ErrNoRows {
		return AppConfigKV{}, false, nil
	}
	if err != nil {
		return AppConfigKV{}, false, err
	}
	return row, true, nil
}

// ListAppConfigKV lists key-values for a store (optional key filter).
func (s *Store) ListAppConfigKV(storeName, keyFilter string) ([]AppConfigKV, error) {
	rows, err := s.db.Query(`
SELECT store, key, label, value FROM appconfig_kvs
WHERE store = ? AND (? = '' OR key = ?) ORDER BY key, label`,
		storeName, keyFilter, keyFilter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppConfigKV
	for rows.Next() {
		var row AppConfigKV
		if err := rows.Scan(&row.Store, &row.Key, &row.Label, &row.Value); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// UpsertFunctionApp creates or updates a Function App with mock invoke response.
func (s *Store) UpsertFunctionApp(subID, rg, name, location, mockResponse string) error {
	if location == "" {
		location = "eastus"
	}
	if mockResponse == "" {
		mockResponse = "ok"
	}
	_, err := s.db.Exec(`
INSERT INTO function_apps (subscription_id, resource_group, name, location, mock_response)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(subscription_id, resource_group, name) DO UPDATE SET
  location=excluded.location, mock_response=excluded.mock_response`,
		subID, rg, name, location, mockResponse)
	return err
}

// GetFunctionApp loads one Function App.
func (s *Store) GetFunctionApp(subID, rg, name string) (FunctionApp, bool, error) {
	var row FunctionApp
	err := s.db.QueryRow(`
SELECT subscription_id, resource_group, name, location, mock_response FROM function_apps
WHERE subscription_id = ? AND resource_group = ? AND name = ?`, subID, rg, name).
		Scan(&row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location, &row.MockResponse)
	if err == sql.ErrNoRows {
		return FunctionApp{}, false, nil
	}
	if err != nil {
		return FunctionApp{}, false, err
	}
	return row, true, nil
}

// GetFunctionAppByName loads a Function App by name (any subscription/RG).
func (s *Store) GetFunctionAppByName(name string) (FunctionApp, bool, error) {
	var row FunctionApp
	err := s.db.QueryRow(`
SELECT subscription_id, resource_group, name, location, mock_response FROM function_apps
WHERE name = ? LIMIT 1`, name).
		Scan(&row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location, &row.MockResponse)
	if err == sql.ErrNoRows {
		return FunctionApp{}, false, nil
	}
	if err != nil {
		return FunctionApp{}, false, err
	}
	return row, true, nil
}

// ListFunctionApps lists Function Apps in a resource group.
func (s *Store) ListFunctionApps(subID, rg string) ([]FunctionApp, error) {
	rows, err := s.db.Query(`
SELECT subscription_id, resource_group, name, location, mock_response FROM function_apps
WHERE subscription_id = ? AND resource_group = ? ORDER BY name`, subID, rg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FunctionApp
	for rows.Next() {
		var row FunctionApp
		if err := rows.Scan(&row.SubscriptionID, &row.ResourceGroup, &row.Name, &row.Location, &row.MockResponse); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// DeleteFunctionApp removes a Function App.
func (s *Store) DeleteFunctionApp(subID, rg, name string) error {
	res, err := s.db.Exec(`DELETE FROM function_apps WHERE subscription_id = ? AND resource_group = ? AND name = ?`,
		subID, rg, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// InvokeFunctionAppMock returns the configured mock response for a Function App.
func (s *Store) InvokeFunctionAppMock(name string) (string, bool, error) {
	row, ok, err := s.GetFunctionAppByName(name)
	if err != nil || !ok {
		return "", ok, err
	}
	return row.MockResponse, true, nil
}

// AppendActivityLog records an ARM mutation for Activity Log.
func (s *Store) AppendActivityLog(caller, operation, resourceID, status, message string) error {
	_, err := s.db.Exec(`
INSERT INTO activity_log (timestamp, caller, operation, resource_id, status, message)
VALUES (?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), caller, operation, resourceID, status, message)
	return err
}

// ListActivityLog returns recent activity log rows.
func (s *Store) ListActivityLog(limit int) ([]map[string]string, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`
SELECT timestamp, caller, operation, resource_id, status, message
FROM activity_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var ts, caller, op, rid, st, msg string
		if err := rows.Scan(&ts, &caller, &op, &rid, &st, &msg); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{
			"timestamp": ts, "caller": caller, "operation": op,
			"resourceId": rid, "status": st, "message": msg,
		})
	}
	return out, rows.Err()
}

// WriteMetric stores a metric sample.
func (s *Store) WriteMetric(name string, value float64, resourceID string) error {
	_, err := s.db.Exec(`INSERT INTO metrics (name, value, timestamp, resource_id) VALUES (?, ?, ?, ?)`,
		name, value, time.Now().UTC().Format(time.RFC3339), resourceID)
	return err
}

// ListMetrics lists recent metrics by name (empty name = all).
func (s *Store) ListMetrics(name string, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`
SELECT name, value, timestamp, resource_id FROM metrics
WHERE (? = '' OR name = ?) ORDER BY id DESC LIMIT ?`, name, name, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var n, ts, rid string
		var v float64
		if err := rows.Scan(&n, &v, &ts, &rid); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"name": n, "value": v, "timestamp": ts, "resourceId": rid})
	}
	return out, rows.Err()
}
