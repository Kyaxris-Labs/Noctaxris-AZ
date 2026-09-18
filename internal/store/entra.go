package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// EntraApp is an app registration theatre row.
type EntraApp struct {
	TenantID    string
	AppID       string
	ObjectID    string
	DisplayName string
	CreatedAt   string
}

// UpsertEntraApp creates or updates an app registration.
func (s *Store) UpsertEntraApp(tenantID, appID, displayName string) (string, error) {
	if appID == "" {
		appID = uuid.NewString()
	}
	obj := uuid.NewString()
	_, err := s.db.Exec(`
INSERT INTO entra_apps (tenant_id, app_id, display_name, created_at, object_id)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, app_id) DO UPDATE SET display_name=excluded.display_name`,
		tenantID, appID, displayName, time.Now().UTC().Format(time.RFC3339), obj)
	return appID, err
}

// GetEntraApp loads one app.
func (s *Store) GetEntraApp(tenantID, appID string) (EntraApp, bool, error) {
	var row EntraApp
	err := s.db.QueryRow(`
SELECT tenant_id, app_id, display_name, created_at, COALESCE(object_id,'') FROM entra_apps
WHERE tenant_id = ? AND (app_id = ? OR object_id = ?)`, tenantID, appID, appID).
		Scan(&row.TenantID, &row.AppID, &row.DisplayName, &row.CreatedAt, &row.ObjectID)
	if err == sql.ErrNoRows {
		return EntraApp{}, false, nil
	}
	if err != nil {
		return EntraApp{}, false, err
	}
	return row, true, nil
}

// ListEntraApps lists apps for a tenant.
func (s *Store) ListEntraApps(tenantID string) ([]EntraApp, error) {
	rows, err := s.db.Query(`
SELECT tenant_id, app_id, display_name, created_at, COALESCE(object_id,'') FROM entra_apps
WHERE tenant_id = ? ORDER BY display_name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EntraApp
	for rows.Next() {
		var row EntraApp
		if err := rows.Scan(&row.TenantID, &row.AppID, &row.DisplayName, &row.CreatedAt, &row.ObjectID); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// DeleteEntraApp deletes an app registration by directory object id.
func (s *Store) DeleteEntraApp(tenantID, objectID string) error {
	res, err := s.db.Exec(`DELETE FROM entra_apps WHERE tenant_id = ? AND object_id = ?`, tenantID, objectID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
