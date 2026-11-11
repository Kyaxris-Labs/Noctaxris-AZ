package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
)

func TestSeedStandaloneSubscriptionIdempotentAndIsolated(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.EnsureRoot(config.DefaultTenantID, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}

	mints := 0
	mint := func(userID string) (string, error) {
		mints++
		return "tok-" + userID, nil
	}
	req := StandaloneSeedRequest{
		SeedName:          "home",
		TenantID:          config.DefaultTenantID,
		LabSubscriptionID: config.DefaultSubscriptionID,
		RootClientID:      "root-client",
	}
	first, err := st.SeedStandaloneSubscription(req, mint)
	if err != nil {
		t.Fatal(err)
	}
	if first.SubscriptionID == config.DefaultSubscriptionID || first.SubscriptionID == config.DefaultTenantID {
		t.Fatalf("subscription id reused lab id %s", first.SubscriptionID)
	}
	if placeholderUUID(first.SubscriptionID) || placeholderUUID(first.UserID) {
		t.Fatalf("placeholder id sub=%s user=%s", first.SubscriptionID, first.UserID)
	}
	if strings.EqualFold(first.UserPrincipalName, "lab-admin@lab.local") || strings.Contains(strings.ToLower(first.UserPrincipalName), "lab-admin") {
		t.Fatalf("user principal %s", first.UserPrincipalName)
	}
	var hash string
	if err := st.DB().QueryRow(`SELECT password_hash FROM entra_users WHERE id = ?`, first.UserID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Fatal("password hash empty")
	}
	match, err := st.UserPasswordMatches(first.UserID, "not-the-password")
	if err != nil || match {
		t.Fatalf("unexpected password match %v %v", match, err)
	}
	ra, ok, err := st.GetRoleAssignment(first.RoleAssignmentID)
	if err != nil || !ok {
		t.Fatalf("assignment ok=%v err=%v", ok, err)
	}
	if ra.PrincipalType != "User" || ra.PrincipalID != first.UserID || ra.Scope != "/subscriptions/"+first.SubscriptionID {
		t.Fatalf("assignment %+v", ra)
	}
	if !strings.HasSuffix(strings.ToLower(ra.RoleDefinitionID), "/8e3af657-a8ff-443c-a75c-2fe8c4bcb635") {
		t.Fatalf("role %s", ra.RoleDefinitionID)
	}
	if err := assertNoDirectoryRole(t, st, first.UserID); err != nil {
		t.Fatal(err)
	}

	second, err := st.SeedStandaloneSubscription(req, mint)
	if err != nil {
		t.Fatal(err)
	}
	if second.AccessToken != first.AccessToken || second.SubscriptionID != first.SubscriptionID || mints != 1 {
		t.Fatalf("reseed rotated mints=%d first=%+v second=%+v", mints, first, second)
	}

	other, err := st.SeedStandaloneSubscription(StandaloneSeedRequest{
		SeedName:          "other",
		TenantID:          config.DefaultTenantID,
		LabSubscriptionID: config.DefaultSubscriptionID,
		RootClientID:      "root-client",
	}, mint)
	if err != nil {
		t.Fatal(err)
	}
	if other.SubscriptionID == first.SubscriptionID || other.AccessToken == first.AccessToken {
		t.Fatalf("second name reused %+v", other)
	}
	if mints != 2 {
		t.Fatalf("mints=%d", mints)
	}

	if _, err := NormalizeStandaloneSeedName("lab admin"); err == nil {
		t.Fatal("expected rejected seed name")
	}
}

func assertNoDirectoryRole(t *testing.T, st *Store, userID string) error {
	t.Helper()
	roles, err := st.ListDirectoryRoles(config.DefaultTenantID)
	if err != nil {
		return err
	}
	for _, role := range roles {
		members, err := st.ListDirectoryRoleMembers(role.ID)
		if err != nil {
			return err
		}
		for _, member := range members {
			if member == userID {
				t.Fatalf("user is a member of directory role %s", role.DisplayName)
			}
		}
	}
	unified, err := st.ListUnifiedRoleAssignments()
	if err != nil {
		return err
	}
	for _, row := range unified {
		if row["principalId"] == userID {
			t.Fatalf("unified directory assignment %+v", row)
		}
	}
	assignments, err := st.ListRoleAssignmentsByScopePrefix("/subscriptions/" + config.DefaultSubscriptionID)
	if err != nil {
		return err
	}
	for _, a := range assignments {
		if a.PrincipalID == userID {
			t.Fatalf("lab subscription assignment %+v", a)
		}
	}
	return nil
}

func TestPlaceholderUUID(t *testing.T) {
	for _, id := range []string{
		"00000000-0000-0000-0000-000000000000",
		"00000000-0000-0000-0000-000000000001",
		"11111111-1111-1111-1111-111111111111",
		"not-a-uuid",
	} {
		if !placeholderUUID(id) {
			t.Fatalf("expected placeholder %s", id)
		}
	}
	if placeholderUUID("3f1c0a2e-7b44-4d19-9c6a-8e2b5d0f1a77") {
		t.Fatal("real uuid rejected")
	}
}
