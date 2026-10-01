package store_test

import (
	"path/filepath"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestListRoleAssignmentsForScopeExactNotPrefix(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rgScope := "/subscriptions/s/resourceGroups/rg"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID: "ra-rg", Scope: rgScope, RoleDefinitionID: authz.RoleOwner,
		PrincipalID: "p1", PrincipalType: "User",
	}); err != nil {
		t.Fatal(err)
	}
	sibling, err := st.ListRoleAssignmentsForScope("/subscriptions/s/resourceGroups/rg_prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(sibling) != 0 {
		t.Fatalf("sibling RG must not inherit prefix scope, got %#v", sibling)
	}
	exact, err := st.ListRoleAssignmentsForScope(rgScope)
	if err != nil || len(exact) != 1 {
		t.Fatalf("exact scope got %d err=%v", len(exact), err)
	}

	ev := &authz.Evaluator{Assignments: st}
	ok, err := ev.Evaluate("p1", false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/s/resourceGroups/rg_prod")
	if err != nil || ok {
		t.Fatal("prefix collision must not authorize sibling RG")
	}
	ok, err = ev.Evaluate("p1", false, "Microsoft.Storage/storageAccounts/write", rgScope)
	if err != nil || !ok {
		t.Fatal("exact RG Owner must authorize")
	}
}

func TestActivityLogSubscriptionLikeEscape(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AppendActivityLog("a", "op", "/subscriptions/sub_1/resourceGroups/rg-a", "Succeeded", "m"); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendActivityLog("b", "op", "/subscriptions/subx1/resourceGroups/rg-b", "Succeeded", "m"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListActivityLogForSubscription("sub_1", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["resourceId"] != "/subscriptions/sub_1/resourceGroups/rg-a" {
		t.Fatalf("LIKE underscore leak: %#v", rows)
	}
}

func TestListMetricsForSubscriptionIsolation(t *testing.T) {
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.WriteMetric("Requests", 9, "/subscriptions/BBBB/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/secret"); err != nil {
		t.Fatal(err)
	}
	if err := st.WriteMetric("Requests", 1, "/subscriptions/AAAA/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/ok"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListMetricsForSubscription("AAAA", "Requests", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 metric, got %#v", rows)
	}
	if rows[0]["resourceId"] != "/subscriptions/AAAA/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/ok" {
		t.Fatalf("wrong row %#v", rows[0])
	}
}
