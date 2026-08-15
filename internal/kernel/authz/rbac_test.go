package authz_test

import (
	"errors"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
)

type memStore struct {
	byScope map[string][]authz.Assignment
	err     error
}

func (m memStore) ListRoleAssignmentsForScope(scope string) ([]authz.Assignment, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.byScope[scope], nil
}

func TestEvaluateRootAndRoles(t *testing.T) {
	ev := &authz.Evaluator{}
	ok, err := ev.Evaluate("x", true, "any", "/subscriptions/s")
	if err != nil || !ok {
		t.Fatal(err)
	}
	ok, err = ev.Evaluate("", false, "a", "/s")
	if err != nil || ok {
		t.Fatal("deny empty")
	}
	var nilEv *authz.Evaluator
	ok, err = nilEv.Evaluate("p", false, "a", "/s")
	if err != nil || ok {
		t.Fatal("nil evaluator")
	}

	store := memStore{byScope: map[string][]authz.Assignment{
		"/subscriptions/s": {{
			PrincipalID: "p1", RoleDefinitionID: authz.RoleOwner, Scope: "/subscriptions/s",
		}},
		"/subscriptions/s/resourceGroups/rg": {{
			PrincipalID: "p2", RoleDefinitionID: authz.RoleContributor, Scope: "/subscriptions/s/resourceGroups/rg",
		}},
		"/subscriptions/s/resourceGroups/rg2": {{
			PrincipalID: "p3", RoleDefinitionID: authz.RoleReader, Scope: "/subscriptions/s/resourceGroups/rg2",
		}},
	}}
	ev = &authz.Evaluator{Assignments: store}
	ok, err = ev.Evaluate("p1", false, "Microsoft.Storage/storageAccounts/write", "/subscriptions/s")
	if err != nil || !ok {
		t.Fatal("owner")
	}
	ok, err = ev.Evaluate("p2", false, "Microsoft.Storage/storageAccounts/write", "/subscriptions/s/resourceGroups/rg")
	if err != nil || !ok {
		t.Fatal("contributor")
	}
	ok, err = ev.Evaluate("p2", false, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/s/resourceGroups/rg")
	if err != nil || ok {
		t.Fatal("contributor blocked on role assignments")
	}
	ok, err = ev.Evaluate("p3", false, "Microsoft.Storage/storageAccounts/read", "/subscriptions/s/resourceGroups/rg2")
	if err != nil || !ok {
		t.Fatal("reader")
	}
	ok, err = ev.Evaluate("p3", false, "Microsoft.Storage/storageAccounts/write", "/subscriptions/s/resourceGroups/rg2")
	if err != nil || ok {
		t.Fatal("reader write deny")
	}
	ok, err = ev.Evaluate("nobody", false, "x/read", "/subscriptions/s")
	if err != nil || ok {
		t.Fatal("default deny")
	}

	ev = &authz.Evaluator{Assignments: memStore{err: errors.New("boom")}}
	_, err = ev.Evaluate("p", false, "a", "/subscriptions/s")
	if err == nil {
		t.Fatal("expected error")
	}
}
