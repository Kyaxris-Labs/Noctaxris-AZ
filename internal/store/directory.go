package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SeededManagementGroupID is the Tenant Root Group inserted by SeedDirectory.
const SeededManagementGroupID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

func opaqueHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DirectoryUser is a Graph user row.
type DirectoryUser struct {
	ID                string
	TenantID          string
	UserPrincipalName string
	DisplayName       string
	Mail              string
	Department        string
	JobTitle          string
	CreatedAt         string
}

// DirectoryGroup is a Graph group row.
type DirectoryGroup struct {
	ID                            string
	TenantID                      string
	DisplayName                   string
	Mail                          string
	SecurityEnabled               bool
	MembershipRule                string
	MembershipRuleProcessingState string
	CreatedAt                     string
}

// DirectoryServicePrincipal is a Graph service principal row.
type DirectoryServicePrincipal struct {
	ID          string
	TenantID    string
	AppID       string
	DisplayName string
	CreatedAt   string
}

// DirectoryDevice is a Graph device row.
type DirectoryDevice struct {
	ID              string
	TenantID        string
	DisplayName     string
	DeviceID        string
	OperatingSystem string
	CreatedAt       string
}

// DirectoryRole is a directory role row.
type DirectoryRole struct {
	ID          string
	TenantID    string
	DisplayName string
	TemplateID  string
	CreatedAt   string
}

// FederatedIdentityCredential is an application FIC.
type FederatedIdentityCredential struct {
	ID                       string
	AppObjectID              string
	Name                     string
	Issuer                   string
	Subject                  string
	Audiences                []string
	ClaimsMatchingExpression string
}

// SeedDirectory writes a small lab graph if users are empty.
func (s *Store) SeedDirectory(tenantID string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM entra_users WHERE tenant_id = ?`, tenantID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	adminID := "11111111-1111-1111-1111-111111111111"
	userID := "22222222-2222-2222-2222-222222222222"
	groupID := "33333333-3333-3333-3333-333333333333"
	nestedID := "44444444-4444-4444-4444-444444444444"
	appObj := "55555555-5555-5555-5555-555555555555"
	appID := "66666666-6666-6666-6666-666666666666"
	spID := "77777777-7777-7777-7777-777777777777"
	gaRole := "88888888-8888-8888-8888-888888888888"
	aaRole := "99999999-9999-9999-9999-999999999999"
	mgID := SeededManagementGroupID
	if _, err := s.db.Exec(`INSERT INTO entra_users (id, tenant_id, user_principal_name, display_name, mail, department, job_title, created_at)
VALUES (?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?)`,
		adminID, tenantID, "lab-admin@lab.local", "Lab Admin", "lab-admin@lab.local", "IT", "Administrator", now,
		userID, tenantID, "lab-user@lab.local", "Lab User", "lab-user@lab.local", "Engineering", "Engineer", now); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO entra_groups (id, tenant_id, display_name, mail, security_enabled, membership_rule, membership_rule_processing_state, created_at)
VALUES (?,?,?,?,1,'','',?), (?,?,?,?,1,'','On',?)`,
		groupID, tenantID, "Lab Admins", "lab-admins@lab.local", now,
		nestedID, tenantID, "Nested Lab", "", now); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO entra_group_members (group_id, member_id, member_type) VALUES (?,?,?), (?,?,?)`,
		groupID, adminID, "user", groupID, nestedID, "group"); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO entra_apps (tenant_id, app_id, display_name, created_at, object_id) VALUES (?,?,?,?,?)`,
		tenantID, appID, "Lab App", now, appObj); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO entra_service_principals (id, tenant_id, app_id, display_name, created_at) VALUES (?,?,?,?,?)`,
		spID, tenantID, appID, "Lab App", now); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO entra_directory_roles (id, tenant_id, display_name, template_id, created_at)
VALUES (?,?,?,?,?), (?,?,?,?,?)`,
		gaRole, tenantID, "Global Administrator", "62e90394-69f5-4237-9190-012177145e10", now,
		aaRole, tenantID, "Application Administrator", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", now); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO entra_directory_role_members (role_id, member_id) VALUES (?,?)`, gaRole, adminID); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO entra_unified_role_assignments (id, principal_id, role_definition_id, directory_scope_id) VALUES (?,?,?,?)`,
		uuid.NewString(), adminID, gaRole, "/"); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO management_groups (id, display_name, tenant_id, parent_id) VALUES (?,?,?, '')`,
		mgID, "Tenant Root Group", tenantID); err != nil {
		return err
	}
	return nil
}

func (s *Store) ListDirectoryUsers(tenantID string) ([]DirectoryUser, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, user_principal_name, display_name, mail, department, job_title, created_at FROM entra_users WHERE tenant_id = ? ORDER BY user_principal_name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryUser
	for rows.Next() {
		var u DirectoryUser
		if err := rows.Scan(&u.ID, &u.TenantID, &u.UserPrincipalName, &u.DisplayName, &u.Mail, &u.Department, &u.JobTitle, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetDirectoryUser(id string) (DirectoryUser, bool, error) {
	var u DirectoryUser
	err := s.db.QueryRow(`SELECT id, tenant_id, user_principal_name, display_name, mail, department, job_title, created_at FROM entra_users WHERE id = ? OR user_principal_name = ?`, id, id).
		Scan(&u.ID, &u.TenantID, &u.UserPrincipalName, &u.DisplayName, &u.Mail, &u.Department, &u.JobTitle, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return DirectoryUser{}, false, nil
	}
	if err != nil {
		return DirectoryUser{}, false, err
	}
	return u, true, nil
}

func (s *Store) PatchDirectoryUser(id, department, jobTitle string) error {
	_, err := s.db.Exec(`UPDATE entra_users SET department = CASE WHEN ? = '' THEN department ELSE ? END, job_title = CASE WHEN ? = '' THEN job_title ELSE ? END WHERE id = ?`,
		department, department, jobTitle, jobTitle, id)
	return err
}

func (s *Store) ListDirectoryGroups(tenantID string) ([]DirectoryGroup, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, display_name, mail, security_enabled, membership_rule, membership_rule_processing_state, created_at FROM entra_groups WHERE tenant_id = ? ORDER BY display_name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryGroup
	for rows.Next() {
		var g DirectoryGroup
		var sec int
		if err := rows.Scan(&g.ID, &g.TenantID, &g.DisplayName, &g.Mail, &sec, &g.MembershipRule, &g.MembershipRuleProcessingState, &g.CreatedAt); err != nil {
			return nil, err
		}
		g.SecurityEnabled = sec != 0
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GetDirectoryGroup(id string) (DirectoryGroup, bool, error) {
	var g DirectoryGroup
	var sec int
	err := s.db.QueryRow(`SELECT id, tenant_id, display_name, mail, security_enabled, membership_rule, membership_rule_processing_state, created_at FROM entra_groups WHERE id = ?`, id).
		Scan(&g.ID, &g.TenantID, &g.DisplayName, &g.Mail, &sec, &g.MembershipRule, &g.MembershipRuleProcessingState, &g.CreatedAt)
	if err == sql.ErrNoRows {
		return DirectoryGroup{}, false, nil
	}
	if err != nil {
		return DirectoryGroup{}, false, err
	}
	g.SecurityEnabled = sec != 0
	return g, true, nil
}

func (s *Store) UpdateGroupRule(id, rule, state string) error {
	_, err := s.db.Exec(`UPDATE entra_groups SET membership_rule = ?, membership_rule_processing_state = ? WHERE id = ?`, rule, state, id)
	return err
}

func (s *Store) AddGroupMember(groupID, memberID, memberType string) error {
	if memberType == "" {
		memberType = "user"
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO entra_group_members (group_id, member_id, member_type) VALUES (?,?,?)`, groupID, memberID, memberType)
	return err
}

func (s *Store) ListGroupMembers(groupID string) ([]string, []string, error) {
	rows, err := s.db.Query(`SELECT member_id, member_type FROM entra_group_members WHERE group_id = ?`, groupID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var ids, types []string
	for rows.Next() {
		var id, typ string
		if err := rows.Scan(&id, &typ); err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		types = append(types, typ)
	}
	return ids, types, rows.Err()
}

func (s *Store) ListServicePrincipals(tenantID string) ([]DirectoryServicePrincipal, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, app_id, display_name, created_at FROM entra_service_principals WHERE tenant_id = ? ORDER BY display_name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryServicePrincipal
	for rows.Next() {
		var sp DirectoryServicePrincipal
		if err := rows.Scan(&sp.ID, &sp.TenantID, &sp.AppID, &sp.DisplayName, &sp.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

func (s *Store) GetServicePrincipal(id string) (DirectoryServicePrincipal, bool, error) {
	var sp DirectoryServicePrincipal
	err := s.db.QueryRow(`SELECT id, tenant_id, app_id, display_name, created_at FROM entra_service_principals WHERE id = ? OR app_id = ?`, id, id).
		Scan(&sp.ID, &sp.TenantID, &sp.AppID, &sp.DisplayName, &sp.CreatedAt)
	if err == sql.ErrNoRows {
		return DirectoryServicePrincipal{}, false, nil
	}
	if err != nil {
		return DirectoryServicePrincipal{}, false, err
	}
	return sp, true, nil
}

func (s *Store) ListDevices(tenantID string) ([]DirectoryDevice, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, display_name, device_id, operating_system, created_at FROM entra_devices WHERE tenant_id = ? ORDER BY display_name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryDevice
	for rows.Next() {
		var d DirectoryDevice
		if err := rows.Scan(&d.ID, &d.TenantID, &d.DisplayName, &d.DeviceID, &d.OperatingSystem, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) GetDevice(id string) (DirectoryDevice, bool, error) {
	var d DirectoryDevice
	err := s.db.QueryRow(`SELECT id, tenant_id, display_name, device_id, operating_system, created_at FROM entra_devices WHERE id = ? OR device_id = ?`, id, id).
		Scan(&d.ID, &d.TenantID, &d.DisplayName, &d.DeviceID, &d.OperatingSystem, &d.CreatedAt)
	if err == sql.ErrNoRows {
		return DirectoryDevice{}, false, nil
	}
	if err != nil {
		return DirectoryDevice{}, false, err
	}
	return d, true, nil
}

func (s *Store) PatchDevice(id, displayName string) error {
	_, err := s.db.Exec(`UPDATE entra_devices SET display_name = CASE WHEN ? = '' THEN display_name ELSE ? END WHERE id = ?`, displayName, displayName, id)
	return err
}

func (s *Store) ListDirectoryRoles(tenantID string) ([]DirectoryRole, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, display_name, template_id, created_at FROM entra_directory_roles WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryRole
	for rows.Next() {
		var r DirectoryRole
		if err := rows.Scan(&r.ID, &r.TenantID, &r.DisplayName, &r.TemplateID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListDirectoryRoleMembers(roleID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT member_id FROM entra_directory_role_members WHERE role_id = ?`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) AddDirectoryRoleMember(roleID, memberID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO entra_directory_role_members (role_id, member_id) VALUES (?,?)`, roleID, memberID)
	return err
}

func (s *Store) ListUnifiedRoleAssignments() ([]map[string]string, error) {
	rows, err := s.db.Query(`SELECT id, principal_id, role_definition_id, directory_scope_id FROM entra_unified_role_assignments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, p, r, d string
		if err := rows.Scan(&id, &p, &r, &d); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{"id": id, "principalId": p, "roleDefinitionId": r, "directoryScopeId": d})
	}
	return out, rows.Err()
}

func (s *Store) ListOwners(resourceID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT owner_id FROM entra_owners WHERE resource_id = ?`, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) AddOwner(resourceID, ownerID, ownerType string) error {
	if ownerType == "" {
		ownerType = "user"
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO entra_owners (resource_id, owner_id, owner_type) VALUES (?,?,?)`, resourceID, ownerID, ownerType)
	return err
}

func (s *Store) ListFICs(appObjectID string) ([]FederatedIdentityCredential, error) {
	rows, err := s.db.Query(`SELECT id, app_object_id, name, issuer, subject, audiences_json, claims_matching_expression FROM entra_fics WHERE app_object_id = ?`, appObjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FederatedIdentityCredential
	for rows.Next() {
		var f FederatedIdentityCredential
		var aud string
		if err := rows.Scan(&f.ID, &f.AppObjectID, &f.Name, &f.Issuer, &f.Subject, &aud, &f.ClaimsMatchingExpression); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(aud), &f.Audiences)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) CreateFIC(appObjectID, name, issuer, subject string, audiences []string, expr string) (FederatedIdentityCredential, error) {
	if len(audiences) == 0 {
		audiences = []string{"api://AzureADTokenExchange"}
	}
	b, _ := json.Marshal(audiences)
	f := FederatedIdentityCredential{
		ID: uuid.NewString(), AppObjectID: appObjectID, Name: name, Issuer: issuer, Subject: subject,
		Audiences: audiences, ClaimsMatchingExpression: expr,
	}
	_, err := s.db.Exec(`INSERT INTO entra_fics (id, app_object_id, name, issuer, subject, audiences_json, claims_matching_expression) VALUES (?,?,?,?,?,?,?)`,
		f.ID, appObjectID, name, issuer, subject, string(b), expr)
	return f, err
}

func (s *Store) FindFIC(issuer, subject, audience string) (FederatedIdentityCredential, bool, error) {
	return s.MatchFIC(issuer, audience, map[string]any{"sub": subject})
}

// MatchFIC finds a federated credential by issuer, audience, and either exact subject or claimsMatchingExpression.
func (s *Store) MatchFIC(issuer, audience string, claims map[string]any) (FederatedIdentityCredential, bool, error) {
	sub := claimString(claims, "sub")
	rows, err := s.db.Query(`SELECT id, app_object_id, name, issuer, subject, audiences_json, claims_matching_expression FROM entra_fics`)
	if err != nil {
		return FederatedIdentityCredential{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var f FederatedIdentityCredential
		var aud string
		if err := rows.Scan(&f.ID, &f.AppObjectID, &f.Name, &f.Issuer, &f.Subject, &aud, &f.ClaimsMatchingExpression); err != nil {
			return FederatedIdentityCredential{}, false, err
		}
		_ = json.Unmarshal([]byte(aud), &f.Audiences)
		if f.Issuer != issuer {
			continue
		}
		if audience != "" && !audienceAllowed(f.Audiences, audience) {
			continue
		}
		expr := ficExpressionValue(f.ClaimsMatchingExpression)
		if expr != "" {
			if EvaluateClaimsMatchingExpression(expr, claims) {
				return f, true, nil
			}
			continue
		}
		if f.Subject != sub {
			continue
		}
		return f, true, nil
	}
	return FederatedIdentityCredential{}, false, rows.Err()
}

func audienceAllowed(audiences []string, audience string) bool {
	if audience == "" {
		return true
	}
	for _, a := range audiences {
		if a == audience {
			return true
		}
	}
	return false
}

// UpsertCAPolicy inserts or replaces a Conditional Access policy. Empty id allocates a UUID.
func (s *Store) UpsertCAPolicy(id, displayName, bodyJSON string, enabled bool) (string, error) {
	if id == "" {
		id = uuid.NewString()
	}
	if bodyJSON == "" {
		bodyJSON = "{}"
	}
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec(`
INSERT INTO entra_ca_policies (id, display_name, body_json, enabled) VALUES (?,?,?,?)
ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, body_json=excluded.body_json, enabled=excluded.enabled`,
		id, displayName, bodyJSON, en)
	return id, err
}

func (s *Store) AddPassword(resourceID, resourceType, displayName, secretHash, hint string) (string, error) {
	id := uuid.NewString()
	_, err := s.db.Exec(`INSERT INTO entra_passwords (id, resource_id, resource_type, display_name, secret_hash, hint, created_at) VALUES (?,?,?,?,?,?,?)`,
		id, resourceID, resourceType, displayName, secretHash, hint, time.Now().UTC().Format(time.RFC3339))
	return id, err
}

func (s *Store) CountKeyCredentials(resourceID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM entra_key_credentials WHERE resource_id = ?`, resourceID).Scan(&n)
	return n, err
}

func (s *Store) AddKeyCredential(resourceID, resourceType, keyPEM, usage, keyType string) (string, error) {
	id := uuid.NewString()
	if usage == "" {
		usage = "Verify"
	}
	if keyType == "" {
		keyType = "AsymmetricX509Cert"
	}
	_, err := s.db.Exec(`INSERT INTO entra_key_credentials (id, resource_id, resource_type, key_pem, usage, key_type) VALUES (?,?,?,?,?,?)`,
		id, resourceID, resourceType, keyPEM, usage, keyType)
	return id, err
}

func (s *Store) ListKeyPEMs(resourceID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT key_pem FROM entra_key_credentials WHERE resource_id = ?`, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListAppRoleAssignedTo(spID string) ([]map[string]string, error) {
	rows, err := s.db.Query(`SELECT id, principal_id, resource_id, app_role_id FROM entra_app_role_assignments WHERE resource_id = ?`, spID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, p, r, a string
		if err := rows.Scan(&id, &p, &r, &a); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{"id": id, "principalId": p, "resourceId": r, "appRoleId": a})
	}
	return out, rows.Err()
}

func (s *Store) PutRefreshToken(tokenHash, principalID string, exp time.Time) error {
	_, err := s.db.Exec(`INSERT INTO refresh_tokens (token_hash, principal_id, expires_at, created_at) VALUES (?,?,?,?)
ON CONFLICT(token_hash) DO UPDATE SET principal_id=excluded.principal_id, expires_at=excluded.expires_at`,
		tokenHash, principalID, exp.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *Store) LookupRefreshToken(tokenHash string, now time.Time) (string, bool, error) {
	var id, exp string
	err := s.db.QueryRow(`SELECT principal_id, expires_at FROM refresh_tokens WHERE token_hash = ?`, tokenHash).Scan(&id, &exp)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	t, perr := time.Parse(time.RFC3339, exp)
	if perr == nil && now.After(t) {
		return "", false, nil
	}
	return id, true, nil
}

func (s *Store) PutDeviceCode(code, principalID string, exp time.Time) error {
	_, err := s.db.Exec(`INSERT INTO device_codes (device_code, principal_id, expires_at) VALUES (?,?,?)
ON CONFLICT(device_code) DO UPDATE SET principal_id=excluded.principal_id, expires_at=excluded.expires_at`,
		opaqueHash(code), principalID, exp.UTC().Format(time.RFC3339))
	return err
}

func (s *Store) LookupDeviceCode(code string, now time.Time) (string, bool, error) {
	var id, exp string
	err := s.db.QueryRow(`SELECT principal_id, expires_at FROM device_codes WHERE device_code = ?`, opaqueHash(code)).Scan(&id, &exp)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	t, perr := time.Parse(time.RFC3339, exp)
	if perr == nil && now.After(t) {
		return "", false, nil
	}
	return id, true, nil
}

func (s *Store) ListCAPolicies() ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT id, display_name, body_json, enabled FROM entra_ca_policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, body string
		var en int
		if err := rows.Scan(&id, &name, &body, &en); err != nil {
			return nil, err
		}
		var parsed any
		if json.Unmarshal([]byte(body), &parsed) != nil {
			parsed = map[string]any{}
		}
		out = append(out, map[string]any{"id": id, "displayName": name, "state": enabledState(en), "conditions": parsed})
	}
	return out, rows.Err()
}

func enabledState(en int) string {
	if en != 0 {
		return "enabled"
	}
	return "disabled"
}

func (s *Store) ListSubscriptions() ([]map[string]string, error) {
	return s.ListSubscriptionsForTenant("")
}

// ListSubscriptionsForTenant lists subscriptions in one tenant. Empty tenantID lists all rows.
func (s *Store) ListSubscriptionsForTenant(tenantID string) ([]map[string]string, error) {
	q := `SELECT id, display_name, state, tenant_id FROM subscriptions`
	var args []any
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	q += ` ORDER BY display_name`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, name, state, tid string
		if err := rows.Scan(&id, &name, &state, &tid); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{"id": id, "displayName": name, "state": state, "tenantId": tid})
	}
	return out, rows.Err()
}

func (s *Store) ListManagementGroups() ([]map[string]string, error) {
	return s.listManagementGroups("", "")
}

// GetManagementGroup loads one management group by id.
func (s *Store) GetManagementGroup(id string) (displayName, tenantID, parentID string, ok bool, err error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", "", "", false, nil
	}
	err = s.db.QueryRow(`SELECT display_name, tenant_id, parent_id FROM management_groups WHERE id = ?`, id).
		Scan(&displayName, &tenantID, &parentID)
	if err == sql.ErrNoRows {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return displayName, tenantID, parentID, true, nil
}

// PutManagementGroup inserts or updates a management group row.
func (s *Store) PutManagementGroup(id, displayName, tenantID, parentID string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("management group id is required")
	}
	_, err := s.db.Exec(`
INSERT INTO management_groups (id, display_name, tenant_id, parent_id) VALUES (?,?,?,?)
ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, tenant_id=excluded.tenant_id, parent_id=excluded.parent_id`,
		id, displayName, tenantID, parentID)
	return err
}

// ListChildManagementGroups returns direct child groups of parentID in tenantID.
func (s *Store) ListChildManagementGroups(parentID, tenantID string) ([]map[string]string, error) {
	parentID = strings.TrimSpace(parentID)
	tenantID = strings.TrimSpace(tenantID)
	if parentID == "" || tenantID == "" {
		return []map[string]string{}, nil
	}
	return s.listManagementGroups(tenantID, parentID)
}

func (s *Store) listManagementGroups(tenantID, parentID string) ([]map[string]string, error) {
	q := `SELECT id, display_name, tenant_id, parent_id FROM management_groups WHERE 1=1`
	var args []any
	if tenantID != "" {
		q += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if parentID != "" {
		q += ` AND parent_id = ?`
		args = append(args, parentID)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, name, tid, parent string
		if err := rows.Scan(&id, &name, &tid, &parent); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{"id": id, "displayName": name, "tenantId": tid, "parentId": parent})
	}
	if out == nil {
		out = []map[string]string{}
	}
	return out, rows.Err()
}

func (s *Store) ListProviderResourcesInSubscription(provider, sub string) ([]ProviderResource, error) {
	rows, err := s.db.Query(`
SELECT provider, subscription_id, resource_group, name, location, properties_json
FROM arm_lab_resources
WHERE subscription_id = ? AND (provider = ? OR provider LIKE ? || '/%')
ORDER BY name`, sub, provider, provider)
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

func (s *Store) UpsertARGResource(id, tableName, typ, name, sub, rg, tenant, props string) error {
	if props == "" {
		props = "{}"
	}
	_, err := s.db.Exec(`INSERT INTO arg_resources (id, table_name, type, name, subscription_id, resource_group, tenant_id, properties_json)
VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET properties_json=excluded.properties_json, type=excluded.type`,
		id, tableName, typ, name, sub, rg, tenant, props)
	return err
}

func (s *Store) ListARGResources(tableName, typeFilter string) ([]map[string]any, error) {
	q := `SELECT id, table_name, type, name, subscription_id, resource_group, tenant_id, properties_json FROM arg_resources WHERE 1=1`
	var args []any
	if tableName != "" {
		q += ` AND lower(table_name) = lower(?)`
		args = append(args, tableName)
	}
	if typeFilter != "" {
		q += ` AND lower(type) = lower(?)`
		args = append(args, typeFilter)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, table, typ, name, sub, rg, tenant, props string
		if err := rows.Scan(&id, &table, &typ, &name, &sub, &rg, &tenant, &props); err != nil {
			return nil, err
		}
		var parsed any
		if json.Unmarshal([]byte(props), &parsed) != nil {
			parsed = map[string]any{}
		}
		out = append(out, map[string]any{
			"id": id, "type": typ, "name": name, "subscriptionId": sub,
			"resourceGroup": rg, "tenantId": tenant, "properties": parsed,
		})
	}
	return out, rows.Err()
}

func (s *Store) InsertLogAnalyticsRow(workspace, tableName string, row map[string]any) error {
	b, _ := json.Marshal(row)
	_, err := s.db.Exec(`INSERT INTO log_analytics_rows (workspace, table_name, row_json) VALUES (?,?,?)`, workspace, tableName, string(b))
	return err
}

func (s *Store) UpsertDiagnosticSetting(id, resourceID, name, workspaceID, props string) error {
	if props == "" {
		props = "{}"
	}
	_, err := s.db.Exec(`INSERT INTO diagnostic_settings (id, resource_id, name, workspace_id, properties_json) VALUES (?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET properties_json=excluded.properties_json, workspace_id=excluded.workspace_id`,
		id, resourceID, name, workspaceID, props)
	return err
}

func (s *Store) GetDiagnosticSetting(id string) (map[string]string, bool, error) {
	var resourceID, name, ws, props string
	err := s.db.QueryRow(`SELECT resource_id, name, workspace_id, properties_json FROM diagnostic_settings WHERE id = ?`, id).
		Scan(&resourceID, &name, &ws, &props)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return map[string]string{"id": id, "resourceId": resourceID, "name": name, "workspaceId": ws, "properties": props}, true, nil
}

func (s *Store) DeleteDiagnosticSetting(id string) error {
	res, err := s.db.Exec(`DELETE FROM diagnostic_settings WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListDiagnosticSettings(resourceID string) ([]map[string]string, error) {
	rows, err := s.db.Query(`SELECT id, resource_id, name, workspace_id, properties_json FROM diagnostic_settings WHERE resource_id = ? OR ? = ''`, resourceID, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, rid, name, ws, props string
		if err := rows.Scan(&id, &rid, &name, &ws, &props); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{"id": id, "resourceId": rid, "name": name, "workspaceId": ws, "properties": props})
	}
	return out, rows.Err()
}

func (s *Store) ResolveEntraApp(tenantID, idOrAppID string) (objectID, appID, displayName string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT COALESCE(NULLIF(object_id,''), app_id), app_id, display_name FROM entra_apps WHERE tenant_id = ? AND (app_id = ? OR object_id = ?)`,
		tenantID, idOrAppID, idOrAppID).Scan(&objectID, &appID, &displayName)
	if err == sql.ErrNoRows {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return objectID, appID, displayName, true, nil
}

func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func HintFromSecret(secret string) string {
	if len(secret) < 3 {
		return secret
	}
	return secret[:3]
}

func NormalizeAppIdFilter(raw string) string {
	raw = strings.TrimSpace(raw)
	const prefix = "applications(appId='"
	if i := strings.Index(raw, prefix); i >= 0 {
		rest := raw[i+len(prefix):]
		if j := strings.Index(rest, "')"); j >= 0 {
			return rest[:j]
		}
	}
	return raw
}
