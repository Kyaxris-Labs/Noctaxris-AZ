package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"

	"github.com/google/uuid"
)

const standaloneSeedDefaultName = "default"

// StandaloneSubscription is one directory user who is Owner of one subscription
// in the configured tenant. The access token is stored so a repeat seed of the
// same name returns it without minting again.
type StandaloneSubscription struct {
	SeedName          string
	SubscriptionID    string
	TenantID          string
	UserID            string
	UserPrincipalName string
	AccessToken       string
	RoleAssignmentID  string
}

// StandaloneSeedRequest names the seed and the ids that must not be reused.
type StandaloneSeedRequest struct {
	SeedName          string
	TenantID          string
	LabSubscriptionID string
	RootClientID      string
}

// StandaloneSeedNameError is a rejected seed name.
type StandaloneSeedNameError struct {
	Reason string
}

func (e *StandaloneSeedNameError) Error() string {
	if e == nil || strings.TrimSpace(e.Reason) == "" {
		return "invalid standalone seed name"
	}
	return e.Reason
}

// NormalizeStandaloneSeedName trims name and applies the default.
func NormalizeStandaloneSeedName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = standaloneSeedDefaultName
	}
	if !validStandaloneSeedName(name) {
		return "", &StandaloneSeedNameError{Reason: "seed name must be 1-64 characters of letters, digits, '.', '_' or '-'"}
	}
	return name, nil
}

func validStandaloneSeedName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// SeedStandaloneSubscription creates or returns the named standalone subscription.
// mint is called only when the name is new. It must return an access token whose
// oid is the new user. A second call with the same name does not call mint.
func (s *Store) SeedStandaloneSubscription(req StandaloneSeedRequest, mint func(userID string) (string, error)) (StandaloneSubscription, error) {
	if s == nil || s.db == nil {
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: store is nil")
	}
	if mint == nil {
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: token mint is required")
	}
	name, err := NormalizeStandaloneSeedName(req.SeedName)
	if err != nil {
		return StandaloneSubscription{}, err
	}
	tenantID := strings.TrimSpace(req.TenantID)
	labSub := strings.TrimSpace(req.LabSubscriptionID)
	if tenantID == "" || labSub == "" {
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: tenant and lab subscription are required")
	}

	s.standaloneMu.Lock()
	defer s.standaloneMu.Unlock()

	existing, ok, err := s.lookupStandaloneSubscription(name)
	if err != nil {
		return StandaloneSubscription{}, err
	}
	if ok {
		return existing, nil
	}

	userID, err := s.allocateStandaloneID(func(id string) bool {
		return standaloneIDRejected(id, tenantID, labSub, req.RootClientID)
	})
	if err != nil {
		return StandaloneSubscription{}, err
	}
	subID, err := s.allocateStandaloneID(func(id string) bool {
		if standaloneIDRejected(id, tenantID, labSub, req.RootClientID) || strings.EqualFold(id, userID) {
			return true
		}
		_, _, _, found, gerr := s.GetSubscription(id)
		return gerr != nil || found
	})
	if err != nil {
		return StandaloneSubscription{}, err
	}

	upn := standaloneUserPrincipalName(userID)
	display := "standalone-" + name
	if err := s.InsertDirectoryUser(DirectoryUser{
		ID:                userID,
		TenantID:          tenantID,
		UserPrincipalName: upn,
		DisplayName:       display,
		Mail:              upn,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return StandaloneSubscription{}, err
	}
	password, err := randomStandaloneSecret()
	if err != nil {
		s.deleteStandaloneUser(userID)
		return StandaloneSubscription{}, err
	}
	hash := HashUserPassword(password)
	if hash == "" {
		s.deleteStandaloneUser(userID)
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: password hash failed")
	}
	if err := s.SetUserPasswordHash(userID, hash); err != nil {
		s.deleteStandaloneUser(userID)
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: %w", err)
	}
	if err := s.PutSubscription(subID, display, "Enabled", tenantID); err != nil {
		s.deleteStandaloneUser(userID)
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: %w", err)
	}

	token, err := mint(userID)
	if err != nil {
		s.deleteStandaloneSubscription(subID)
		s.deleteStandaloneUser(userID)
		return StandaloneSubscription{}, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		s.deleteStandaloneSubscription(subID)
		s.deleteStandaloneUser(userID)
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: empty access token")
	}

	raID := uuid.NewString()
	scope := "/subscriptions/" + subID
	if err := s.UpsertRoleAssignment(authz.Assignment{
		ID:               raID,
		Scope:            scope,
		RoleDefinitionID: authz.RoleOwner,
		PrincipalID:      userID,
		PrincipalType:    "User",
	}); err != nil {
		_ = s.DeleteAccessToken(authn.HashToken(token))
		s.deleteStandaloneSubscription(subID)
		s.deleteStandaloneUser(userID)
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: %w", err)
	}

	_, err = s.db.Exec(`INSERT INTO standalone_subscriptions
(seed_name, subscription_id, tenant_id, user_id, user_principal_name, access_token, role_assignment_id)
VALUES (?,?,?,?,?,?,?)`,
		name, subID, tenantID, userID, upn, token, raID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			got, found, lerr := s.lookupStandaloneSubscription(name)
			if lerr != nil {
				return StandaloneSubscription{}, lerr
			}
			if found {
				return got, nil
			}
		}
		_, _ = s.db.Exec(`DELETE FROM role_assignments WHERE id = ?`, raID)
		_ = s.DeleteAccessToken(authn.HashToken(token))
		s.deleteStandaloneSubscription(subID)
		s.deleteStandaloneUser(userID)
		return StandaloneSubscription{}, fmt.Errorf("seed standalone subscription: record seed: %w", err)
	}
	return StandaloneSubscription{
		SeedName:          name,
		SubscriptionID:    subID,
		TenantID:          tenantID,
		UserID:            userID,
		UserPrincipalName: upn,
		AccessToken:       token,
		RoleAssignmentID:  raID,
	}, nil
}

func (s *Store) lookupStandaloneSubscription(name string) (StandaloneSubscription, bool, error) {
	var out StandaloneSubscription
	err := s.db.QueryRow(`SELECT seed_name, subscription_id, tenant_id, user_id, user_principal_name, access_token, role_assignment_id
FROM standalone_subscriptions WHERE seed_name = ?`, name).Scan(
		&out.SeedName, &out.SubscriptionID, &out.TenantID, &out.UserID, &out.UserPrincipalName, &out.AccessToken, &out.RoleAssignmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return StandaloneSubscription{}, false, nil
	}
	if err != nil {
		return StandaloneSubscription{}, false, fmt.Errorf("seed standalone subscription: lookup %s: %w", name, err)
	}
	if strings.TrimSpace(out.AccessToken) == "" || strings.TrimSpace(out.SubscriptionID) == "" {
		return StandaloneSubscription{}, false, fmt.Errorf("seed standalone subscription: stored seed %s is incomplete", name)
	}
	return out, true, nil
}

func (s *Store) allocateStandaloneID(reject func(string) bool) (string, error) {
	for i := 0; i < 64; i++ {
		id := uuid.NewString()
		if reject != nil && reject(id) {
			continue
		}
		return id, nil
	}
	return "", fmt.Errorf("seed standalone subscription: exhausted id attempts")
}

func standaloneIDRejected(id, tenantID, labSubscriptionID, rootClientID string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" || placeholderUUID(id) {
		return true
	}
	for _, banned := range []string{tenantID, labSubscriptionID, rootClientID} {
		if banned != "" && id == strings.ToLower(strings.TrimSpace(banned)) {
			return true
		}
	}
	return false
}

func placeholderUUID(id string) bool {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil {
		return true
	}
	hex := strings.ReplaceAll(strings.ToLower(parsed.String()), "-", "")
	if len(hex) != 32 {
		return true
	}
	allSame := true
	for i := 1; i < len(hex); i++ {
		if hex[i] != hex[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}
	// Sequential nil-like ids such as 00000000-0000-0000-0000-000000000001.
	zeros := 0
	for _, c := range hex {
		if c != '0' {
			break
		}
		zeros++
	}
	return zeros >= 31
}

func standaloneUserPrincipalName(userID string) string {
	compact := strings.ReplaceAll(strings.ToLower(userID), "-", "")
	if len(compact) > 12 {
		compact = compact[:12]
	}
	return "u-" + compact + "@users.directory"
}

func randomStandaloneSecret() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("seed standalone subscription: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func (s *Store) deleteStandaloneUser(id string) {
	_, _ = s.db.Exec(`DELETE FROM entra_users WHERE id = ?`, id)
}

func (s *Store) deleteStandaloneSubscription(id string) {
	_, _ = s.db.Exec(`DELETE FROM subscriptions WHERE id = ?`, id)
}
