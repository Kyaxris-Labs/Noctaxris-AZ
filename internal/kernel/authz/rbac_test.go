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

type groupMemStore struct {
	memStore
	members map[string][][2]string
	listErr error
}

func (g groupMemStore) ListGroupMembers(groupID string) ([]string, []string, error) {
	if g.listErr != nil {
		return nil, nil, g.listErr
	}
	rows := g.members[groupID]
	ids := make([]string, 0, len(rows))
	types := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row[0])
		types = append(types, row[1])
	}
	return ids, types, nil
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

func TestEvaluateGroupMemberInheritsReader(t *testing.T) {
	const (
		groupID  = "group-1"
		memberID = "user-member"
		otherID  = "user-other"
		nestedID = "group-nested"
		leafID   = "user-nested-leaf"
		rgScope  = "/subscriptions/s/resourceGroups/rg"
	)
	base := memStore{byScope: map[string][]authz.Assignment{
		rgScope: {{
			PrincipalID:      groupID,
			PrincipalType:    "Group",
			RoleDefinitionID: authz.RoleReader,
			Scope:            rgScope,
		}},
	}}
	store := groupMemStore{
		memStore: base,
		members: map[string][][2]string{
			groupID:  {{memberID, "user"}, {nestedID, "group"}},
			nestedID: {{leafID, "user"}},
		},
	}
	ev := &authz.Evaluator{Assignments: store}
	action := "Microsoft.Resources/subscriptions/resourceGroups/read"
	ok, err := ev.Evaluate(memberID, false, action, rgScope)
	if err != nil || !ok {
		t.Fatalf("member: ok=%v err=%v", ok, err)
	}
	ok, err = ev.Evaluate(leafID, false, action, rgScope)
	if err != nil || !ok {
		t.Fatalf("nested member: ok=%v err=%v", ok, err)
	}
	ok, err = ev.Evaluate(otherID, false, action, rgScope)
	if err != nil || ok {
		t.Fatal("non-member must be denied")
	}
}

func TestEvaluateBuiltInQueryAndGraphActions(t *testing.T) {
	scope := "/subscriptions/s"
	store := memStore{byScope: map[string][]authz.Assignment{
		scope: {
			{PrincipalID: "reader", RoleDefinitionID: authz.RoleReader, Scope: scope},
			{PrincipalID: "logs", RoleDefinitionID: authz.RoleLogAnalyticsReader, Scope: scope},
			{PrincipalID: "logs-alias", RoleDefinitionID: "73c42c96-874c-492b-b04d-ab87d988a1e9", Scope: scope},
			{PrincipalID: "mon", RoleDefinitionID: authz.RoleMonitoringReader, Scope: scope},
			{PrincipalID: "acr", RoleDefinitionID: authz.RoleAcrPull, Scope: scope},
			{PrincipalID: "eh", RoleDefinitionID: authz.RoleEventHubsDataReceiver, Scope: scope},
			{PrincipalID: "la-data", RoleDefinitionID: authz.RoleLogAnalyticsDataReader, Scope: scope},
		},
	}}
	ev := &authz.Evaluator{Assignments: store}

	query := "Microsoft.OperationalInsights/workspaces/query/read"
	queryAction := "Microsoft.OperationalInsights/workspaces/query/action"
	arg := "Microsoft.ResourceGraph/resources/read"
	if ok, err := ev.Evaluate("reader", false, query, scope); err != nil || !ok {
		t.Fatal("reader query/read")
	}
	if ok, err := ev.Evaluate("reader", false, queryAction, scope); err != nil || !ok {
		t.Fatal("reader query/action")
	}
	if ok, err := ev.Evaluate("reader", false, arg, scope); err != nil || !ok {
		t.Fatal("reader ARG")
	}
	if ok, err := ev.Evaluate("logs", false, queryAction, scope); err != nil || !ok {
		t.Fatal("log analytics reader query")
	}
	if ok, err := ev.Evaluate("logs-alias", false, query, scope); err != nil || !ok {
		t.Fatal("log analytics reader alias GUID")
	}
	if ok, err := ev.Evaluate("mon", false, "Microsoft.Insights/metrics/read", scope); err != nil || !ok {
		t.Fatal("monitoring reader")
	}
	if ok, err := ev.Evaluate("la-data", false, query, scope); err != nil || !ok {
		t.Fatal("log analytics data reader query")
	}
	if ok, err := ev.Evaluate("la-data", false, "Microsoft.Storage/storageAccounts/read", scope); err != nil || ok {
		t.Fatal("data reader must not get */read")
	}
	if ok, err := ev.Evaluate("acr", false, "Microsoft.ContainerRegistry/registries/pull/read", scope); err != nil || !ok {
		t.Fatal("acr pull")
	}
	if ok, err := ev.Evaluate("acr", false, "Microsoft.Storage/storageAccounts/read", scope); err != nil || ok {
		t.Fatal("acr pull must not grant storage")
	}
	if ok, err := ev.Evaluate("eh", false, "Microsoft.EventHub/namespaces/eventhubs/receive/action", scope); err != nil || !ok {
		t.Fatal("event hubs receive")
	}
	if ok, err := ev.Evaluate("eh", false, "Microsoft.Storage/storageAccounts/read", scope); err != nil || ok {
		t.Fatal("event hubs receiver must not grant storage")
	}
}
