package store

import (
	"database/sql"
	"fmt"
	"strings"
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

// ListFunctionAppsInSubscription lists Function Apps across resource groups.
func (s *Store) ListFunctionAppsInSubscription(subID string) ([]FunctionApp, error) {
	rows, err := s.db.Query(`
SELECT subscription_id, resource_group, name, location, mock_response FROM function_apps
WHERE subscription_id = ? ORDER BY name`, subID)
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

// ActivityLogRow is one Microsoft.Insights activity event.
type ActivityLogRow struct {
	Timestamp    time.Time
	Caller       string
	Operation    string
	ResourceID   string
	Status       string
	Message      string
	ClientIP     string
	IdentityJSON string
}

// AppendActivityLog records an ARM mutation for Activity Log using wall clock.
func (s *Store) AppendActivityLog(caller, operation, resourceID, status, message string) error {
	return s.AppendActivityLogRow(ActivityLogRow{
		Timestamp:  time.Now().UTC(),
		Caller:     caller,
		Operation:  operation,
		ResourceID: resourceID,
		Status:     status,
		Message:    message,
	})
}

// AppendActivityLogRow records a fully specified Activity Log event.
func (s *Store) AppendActivityLogRow(row ActivityLogRow) error {
	ts := row.Timestamp.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	_, err := s.db.Exec(`
INSERT INTO activity_log (timestamp, caller, operation, resource_id, status, message, client_ip, identity_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts.Format(time.RFC3339Nano), row.Caller, row.Operation, row.ResourceID, row.Status, row.Message, row.ClientIP, row.IdentityJSON)
	return err
}

// ListActivityLog returns recent activity log rows.
func (s *Store) ListActivityLog(limit int) ([]map[string]string, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`
SELECT timestamp, caller, operation, resource_id, status, message, client_ip, identity_json
FROM activity_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var ts, caller, op, rid, st, msg, ip, ident string
		if err := rows.Scan(&ts, &caller, &op, &rid, &st, &msg, &ip, &ident); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{
			"timestamp": ts, "caller": caller, "operation": op,
			"resourceId": rid, "status": st, "message": msg,
			"clientIp": ip, "identity": ident,
		})
	}
	return out, rows.Err()
}

// ListActivityLogForSubscription returns recent activity rows whose resource_id is that subscription or a child of it.
func (s *Store) ListActivityLogForSubscription(subscriptionID string, limit int) ([]map[string]string, error) {
	subscriptionID = strings.TrimSpace(subscriptionID)
	if subscriptionID == "" {
		return []map[string]string{}, nil
	}
	if limit <= 0 {
		limit = 50
	}
	prefix := "/subscriptions/" + subscriptionID
	rows, err := s.db.Query(`
SELECT timestamp, caller, operation, resource_id, status, message, client_ip, identity_json
FROM activity_log
WHERE resource_id = ? OR resource_id LIKE ? || '/%'
ORDER BY id DESC LIMIT ?`, prefix, prefix, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var ts, caller, op, rid, st, msg, ip, ident string
		if err := rows.Scan(&ts, &caller, &op, &rid, &st, &msg, &ip, &ident); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{
			"timestamp": ts, "caller": caller, "operation": op,
			"resourceId": rid, "status": st, "message": msg,
			"clientIp": ip, "identity": ident,
		})
	}
	if out == nil {
		out = []map[string]string{}
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

// SetAppConfigFeatureFlag upserts a feature flag.
func (s *Store) SetAppConfigFeatureFlag(storeName, name string, enabled bool, conditionsJSON string) error {
	if conditionsJSON == "" {
		conditionsJSON = "{}"
	}
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec(`
INSERT INTO appconfig_feature_flags (store, name, enabled, conditions_json)
VALUES (?, ?, ?, ?)
ON CONFLICT(store, name) DO UPDATE SET enabled=excluded.enabled, conditions_json=excluded.conditions_json`,
		storeName, name, en, conditionsJSON)
	return err
}

// GetAppConfigFeatureFlag loads a feature flag.
func (s *Store) GetAppConfigFeatureFlag(storeName, name string) (enabled bool, conditionsJSON string, ok bool, err error) {
	var en int
	err = s.db.QueryRow(`
SELECT enabled, conditions_json FROM appconfig_feature_flags WHERE store = ? AND name = ?`,
		storeName, name).Scan(&en, &conditionsJSON)
	if err == sql.ErrNoRows {
		return false, "", false, nil
	}
	if err != nil {
		return false, "", false, err
	}
	return en == 1, conditionsJSON, true, nil
}

// ListAppConfigFeatureFlags lists feature flags for a store.
func (s *Store) ListAppConfigFeatureFlags(storeName string) ([]struct {
	Name           string
	Enabled        bool
	ConditionsJSON string
}, error) {
	rows, err := s.db.Query(`
SELECT name, enabled, conditions_json FROM appconfig_feature_flags WHERE store = ? ORDER BY name`, storeName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		Name           string
		Enabled        bool
		ConditionsJSON string
	}
	for rows.Next() {
		var name, cond string
		var en int
		if err := rows.Scan(&name, &en, &cond); err != nil {
			return nil, err
		}
		out = append(out, struct {
			Name           string
			Enabled        bool
			ConditionsJSON string
		}{name, en == 1, cond})
	}
	return out, rows.Err()
}

// AppConfigSnapshot is a captured KV snapshot row.
type AppConfigSnapshot struct {
	Store     string
	Name      string
	Status    string
	CreatedAt string
}

// UpsertAppConfigSnapshot creates a snapshot and copies the current KV set (including labels).
// A later PUT on an existing name updates status only; captured KV stays frozen.
func (s *Store) UpsertAppConfigSnapshot(storeName, name, status string) error {
	if status == "" {
		status = "ready"
	}
	_, _, exists, err := s.GetAppConfigSnapshot(storeName, name)
	if err != nil {
		return err
	}
	if exists {
		_, err := s.db.Exec(`UPDATE appconfig_snapshots SET status = ? WHERE store = ? AND name = ?`,
			status, storeName, name)
		return err
	}
	if _, err := s.db.Exec(`
INSERT INTO appconfig_snapshots (store, name, status, created_at)
VALUES (?, ?, ?, ?)`,
		storeName, name, status, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	kvs, err := s.ListAppConfigKV(storeName, "")
	if err != nil {
		return err
	}
	for _, kv := range kvs {
		if _, err := s.db.Exec(`
INSERT INTO appconfig_snapshot_kvs (store, snapshot, key, label, value) VALUES (?, ?, ?, ?, ?)`,
			storeName, name, kv.Key, kv.Label, kv.Value); err != nil {
			return err
		}
	}
	return nil
}

// GetAppConfigSnapshot loads a snapshot.
func (s *Store) GetAppConfigSnapshot(storeName, name string) (status, createdAt string, ok bool, err error) {
	err = s.db.QueryRow(`
SELECT status, created_at FROM appconfig_snapshots WHERE store = ? AND name = ?`, storeName, name).
		Scan(&status, &createdAt)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return status, createdAt, true, nil
}

// ListAppConfigSnapshots lists snapshots for a store.
func (s *Store) ListAppConfigSnapshots(storeName string) ([]AppConfigSnapshot, error) {
	rows, err := s.db.Query(`
SELECT store, name, status, created_at FROM appconfig_snapshots WHERE store = ? ORDER BY name`, storeName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppConfigSnapshot
	for rows.Next() {
		var row AppConfigSnapshot
		if err := rows.Scan(&row.Store, &row.Name, &row.Status, &row.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if out == nil {
		out = []AppConfigSnapshot{}
	}
	return out, rows.Err()
}

// ListAppConfigSnapshotKV returns captured key-values. Empty labelFilter returns all labels.
func (s *Store) ListAppConfigSnapshotKV(storeName, snapshot, labelFilter string) ([]AppConfigKV, error) {
	rows, err := s.db.Query(`
SELECT store, key, label, value FROM appconfig_snapshot_kvs
WHERE store = ? AND snapshot = ? AND (? = '' OR label = ?)
ORDER BY key, label`,
		storeName, snapshot, labelFilter, labelFilter)
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
	if out == nil {
		out = []AppConfigKV{}
	}
	return out, rows.Err()
}

// IngestLogAnalyticsRow stores a Log Analytics row.
func (s *Store) IngestLogAnalyticsRow(workspace, tableName, rowJSON string) error {
	_, err := s.db.Exec(`
INSERT INTO log_analytics_rows (workspace, table_name, row_json) VALUES (?, ?, ?)`,
		workspace, tableName, rowJSON)
	return err
}

// CaptureEmail stores a captured email message.
func (s *Store) CaptureEmail(service, to, subject, body string) error {
	_, err := s.db.Exec(`
INSERT INTO email_messages (service_name, to_addr, subject, body, inserted_at)
VALUES (?, ?, ?, ?, datetime('now'))`, service, to, subject, body)
	return err
}
