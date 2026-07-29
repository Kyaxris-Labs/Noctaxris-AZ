package store

import (
	"database/sql"
	"fmt"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
)

// ListRoleAssignmentsForScope implements authz.AssignmentStore with exact scope match
// plus parent subscription scope when listing under a resource group.
func (s *Store) ListRoleAssignmentsForScope(scope string) ([]authz.Assignment, error) {
	rows, err := s.db.Query(`SELECT id, scope, role_definition_id, principal_id FROM role_assignments WHERE scope = ? OR ? LIKE scope || '%'`, scope, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authz.Assignment
	for rows.Next() {
		var a authz.Assignment
		if err := rows.Scan(&a.ID, &a.Scope, &a.RoleDefinitionID, &a.PrincipalID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpsertRoleAssignment stores a role assignment.
func (s *Store) UpsertRoleAssignment(a authz.Assignment) error {
	pt := a.PrincipalType
	if pt == "" {
		pt = "ServicePrincipal"
	}
	_, err := s.db.Exec(`
INSERT INTO role_assignments (id, scope, role_definition_id, principal_id, principal_type)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET scope=excluded.scope, role_definition_id=excluded.role_definition_id, principal_id=excluded.principal_id, principal_type=excluded.principal_type`,
		a.ID, a.Scope, a.RoleDefinitionID, a.PrincipalID, pt)
	return err
}

// GetRoleAssignment loads one assignment.
func (s *Store) GetRoleAssignment(id string) (authz.Assignment, bool, error) {
	var a authz.Assignment
	err := s.db.QueryRow(`SELECT id, scope, role_definition_id, principal_id, principal_type FROM role_assignments WHERE id = ?`, id).
		Scan(&a.ID, &a.Scope, &a.RoleDefinitionID, &a.PrincipalID, &a.PrincipalType)
	if err == sql.ErrNoRows {
		return authz.Assignment{}, false, nil
	}
	if err != nil {
		return authz.Assignment{}, false, err
	}
	return a, true, nil
}

// GetSubscription returns subscription metadata.
func (s *Store) GetSubscription(id string) (displayName, state, tenantID string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT display_name, state, tenant_id FROM subscriptions WHERE id = ?`, id).
		Scan(&displayName, &state, &tenantID)
	if err == sql.ErrNoRows {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return displayName, state, tenantID, true, nil
}

// UpsertResourceGroup creates or updates a resource group.
func (s *Store) UpsertResourceGroup(subID, name, location string) error {
	_, err := s.db.Exec(`
INSERT INTO resource_groups (subscription_id, name, location) VALUES (?, ?, ?)
ON CONFLICT(subscription_id, name) DO UPDATE SET location=excluded.location`,
		subID, name, location)
	return err
}

// GetResourceGroup loads a resource group.
func (s *Store) GetResourceGroup(subID, name string) (location string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT location FROM resource_groups WHERE subscription_id = ? AND name = ?`, subID, name).
		Scan(&location)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return location, true, nil
}

// ListResourceGroups lists RGs in a subscription.
func (s *Store) ListResourceGroups(subID string) ([]struct{ Name, Location string }, error) {
	rows, err := s.db.Query(`SELECT name, location FROM resource_groups WHERE subscription_id = ? ORDER BY name`, subID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct{ Name, Location string }
	for rows.Next() {
		var n, loc string
		if err := rows.Scan(&n, &loc); err != nil {
			return nil, err
		}
		out = append(out, struct{ Name, Location string }{n, loc})
	}
	return out, rows.Err()
}

// RequireDB is a compile-time helper for unused import hygiene in generated code.
func RequireDB() error {
	if false {
		return fmt.Errorf("unused")
	}
	return nil
}
