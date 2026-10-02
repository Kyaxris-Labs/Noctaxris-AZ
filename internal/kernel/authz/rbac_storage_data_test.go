package authz_test

import (
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
)

func TestStorageDataRolesAndOwnerDenied(t *testing.T) {
	scope := "/subscriptions/s/resourceGroups/rg"
	store := memStore{byScope: map[string][]authz.Assignment{
		scope: {
			{PrincipalID: "owner", RoleDefinitionID: authz.RoleOwner, Scope: scope},
			{PrincipalID: "blob", RoleDefinitionID: authz.RoleStorageBlobDataContributor, Scope: scope},
			{PrincipalID: "bread", RoleDefinitionID: authz.RoleStorageBlobDataReader, Scope: scope},
			{PrincipalID: "table", RoleDefinitionID: authz.RoleStorageTableDataContributor, Scope: scope},
			{PrincipalID: "tread", RoleDefinitionID: authz.RoleStorageTableDataReader, Scope: scope},
		},
	}}
	ev := &authz.Evaluator{Assignments: store}
	blobRead := "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
	blobWrite := "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
	tableRead := "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"
	tableWrite := "Microsoft.Storage/storageAccounts/tableServices/tables/entities/write"
	acctRead := "Microsoft.Storage/storageAccounts/read"

	if ok, err := ev.Evaluate("owner", false, blobRead, scope); err != nil || ok {
		t.Fatal("Owner must not get blob data read")
	}
	if ok, err := ev.Evaluate("owner", false, acctRead, scope); err != nil || !ok {
		t.Fatal("Owner must keep account read")
	}
	if ok, err := ev.Evaluate("blob", false, blobWrite, scope); err != nil || !ok {
		t.Fatal("Blob Data Contributor must write")
	}
	if ok, err := ev.Evaluate("bread", false, blobRead, scope); err != nil || !ok {
		t.Fatal("Blob Data Reader must read")
	}
	if ok, err := ev.Evaluate("bread", false, blobWrite, scope); err != nil || ok {
		t.Fatal("Blob Data Reader must not write")
	}
	if ok, err := ev.Evaluate("table", false, tableWrite, scope); err != nil || !ok {
		t.Fatal("Table Data Contributor must write")
	}
	if ok, err := ev.Evaluate("tread", false, tableRead, scope); err != nil || !ok {
		t.Fatal("Table Data Reader must read")
	}
	if ok, err := ev.Evaluate("tread", false, tableWrite, scope); err != nil || ok {
		t.Fatal("Table Data Reader must not write")
	}
}

func TestAcrPullDoesNotGrantRegistriesReadAlone(t *testing.T) {
	scope := "/subscriptions/s"
	store := memStore{byScope: map[string][]authz.Assignment{
		scope: {
			{PrincipalID: "pull", RoleDefinitionID: authz.RoleAcrPull, Scope: scope},
			{PrincipalID: "reader", RoleDefinitionID: authz.RoleReader, Scope: scope},
		},
	}}
	ev := &authz.Evaluator{Assignments: store}
	pull := "Microsoft.ContainerRegistry/registries/pull/read"
	regRead := "Microsoft.ContainerRegistry/registries/read"
	if ok, err := ev.Evaluate("pull", false, pull, scope); err != nil || !ok {
		t.Fatal("AcrPull must grant pull/read")
	}
	if ok, err := ev.Evaluate("pull", false, regRead, scope); err != nil || ok {
		t.Fatal("AcrPull must not grant ARM registries/read via pull helper")
	}
	if ok, err := ev.Evaluate("reader", false, regRead, scope); err != nil || !ok {
		t.Fatal("Reader must keep registries/read")
	}
	if ok, err := ev.Evaluate("reader", false, pull, scope); err != nil || ok {
		t.Fatal("Reader must not pull")
	}
}
