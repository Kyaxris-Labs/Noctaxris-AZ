package authz_test

import (
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
)

func TestOwnerDeniedEventHubsDataPlaneSendReceive(t *testing.T) {
	scope := "/subscriptions/s/resourceGroups/rg"
	store := memStore{byScope: map[string][]authz.Assignment{
		scope: {
			{PrincipalID: "owner", RoleDefinitionID: authz.RoleOwner, Scope: scope},
			{PrincipalID: "contrib", RoleDefinitionID: authz.RoleContributor, Scope: scope},
			{PrincipalID: "eh-owner", RoleDefinitionID: authz.RoleEventHubsDataOwner, Scope: scope},
		},
	}}
	ev := &authz.Evaluator{Assignments: store}
	send := "Microsoft.EventHub/namespaces/eventhubs/send/action"
	recv := "Microsoft.EventHub/namespaces/eventhubs/receive/action"
	nsRead := "Microsoft.EventHub/namespaces/read"
	for _, pid := range []string{"owner", "contrib"} {
		if ok, err := ev.Evaluate(pid, false, send, scope); err != nil || ok {
			t.Fatalf("%s must not send: ok=%v err=%v", pid, ok, err)
		}
		if ok, err := ev.Evaluate(pid, false, recv, scope); err != nil || ok {
			t.Fatalf("%s must not receive: ok=%v err=%v", pid, ok, err)
		}
		if ok, err := ev.Evaluate(pid, false, nsRead, scope); err != nil || !ok {
			t.Fatalf("%s must keep namespace read: ok=%v err=%v", pid, ok, err)
		}
	}
	if ok, err := ev.Evaluate("eh-owner", false, send, scope); err != nil || !ok {
		t.Fatal("Event Hubs Data Owner must send")
	}
	if ok, err := ev.Evaluate("eh-owner", false, recv, scope); err != nil || !ok {
		t.Fatal("Event Hubs Data Owner must receive")
	}
}

func TestEventGridSubscriptionWriteIsNotDataPlaneSend(t *testing.T) {
	scope := "/subscriptions/s/resourceGroups/rg"
	store := memStore{byScope: map[string][]authz.Assignment{
		scope: {
			{PrincipalID: "owner", RoleDefinitionID: authz.RoleOwner, Scope: scope},
			{PrincipalID: "sender", RoleDefinitionID: authz.RoleEventGridDataSender, Scope: scope},
		},
	}}
	ev := &authz.Evaluator{Assignments: store}
	subWrite := "Microsoft.EventGrid/eventSubscriptions/write"
	send := "Microsoft.EventGrid/topics/send/action"
	if ok, err := ev.Evaluate("owner", false, subWrite, scope); err != nil || !ok {
		t.Fatal("Owner must manage eventSubscriptions/write")
	}
	if ok, err := ev.Evaluate("sender", false, subWrite, scope); err != nil || ok {
		t.Fatal("Event Grid Data Sender must not get eventSubscriptions/write")
	}
	if ok, err := ev.Evaluate("sender", false, send, scope); err != nil || !ok {
		t.Fatal("Event Grid Data Sender must publish")
	}
	if ok, err := ev.Evaluate("owner", false, send, scope); err != nil || ok {
		t.Fatal("Owner must not get dedicated Event Grid send")
	}
}

func TestAKSClusterCredentialRolesAreSplit(t *testing.T) {
	scope := "/subscriptions/s/resourceGroups/rg"
	store := memStore{byScope: map[string][]authz.Assignment{
		scope: {
			{PrincipalID: "admin", RoleDefinitionID: authz.RoleAKSClusterAdminCredential, Scope: scope},
			{PrincipalID: "user", RoleDefinitionID: authz.RoleAKSClusterUserCredential, Scope: scope},
		},
	}}
	ev := &authz.Evaluator{Assignments: store}
	adminAct := "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
	userAct := "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"
	if ok, err := ev.Evaluate("admin", false, adminAct, scope); err != nil || !ok {
		t.Fatal("cluster admin credential role must grant admin list")
	}
	if ok, err := ev.Evaluate("admin", false, userAct, scope); err != nil || ok {
		t.Fatal("cluster admin credential role must not grant user list")
	}
	if ok, err := ev.Evaluate("user", false, userAct, scope); err != nil || !ok {
		t.Fatal("cluster user credential role must grant user list")
	}
	if ok, err := ev.Evaluate("user", false, adminAct, scope); err != nil || ok {
		t.Fatal("cluster user credential role must not grant admin list")
	}
}

func TestAppConfigDataRoleGUIDsMatchAzurePublished(t *testing.T) {
	reader := authz.RoleAppConfigDataReader
	owner := authz.RoleAppConfigDataOwner
	if !strings.HasSuffix(reader, "/516239f1-63e1-4d78-a4de-a74fb236a071") {
		t.Fatalf("App Configuration Data Reader GUID: %s", reader)
	}
	if !strings.HasSuffix(owner, "/5ae67dd6-50cb-40e7-96ff-dc2bfa4b606b") {
		t.Fatalf("App Configuration Data Owner GUID: %s", owner)
	}
	scope := "/subscriptions/s/resourceGroups/rg"
	store := memStore{byScope: map[string][]authz.Assignment{
		scope: {{
			PrincipalID:      "reader",
			RoleDefinitionID: "516239f1-63e1-4d78-a4de-a74fb236a071",
			Scope:            scope,
		}},
	}}
	ev := &authz.Evaluator{Assignments: store}
	act := "Microsoft.AppConfiguration/configurationStores/keyValues/read"
	if ok, err := ev.Evaluate("reader", false, act, scope); err != nil || !ok {
		t.Fatalf("published Data Reader GUID must grant keyValues/read: ok=%v err=%v", ok, err)
	}
}
