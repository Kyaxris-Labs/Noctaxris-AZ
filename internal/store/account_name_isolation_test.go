package store_test

import (
	"testing"
)

func TestAmbiguousNamesAreNotFoundAndKeysStayOnTheRow(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	keyA, err := st.UpsertStorageAccount("sub-a", "rg-a", "acct", "eastus", "127.0.0.1:4599")
	if err != nil || keyA == "" {
		t.Fatal(err)
	}
	keySame, err := st.UpsertStorageAccount("sub-a", "rg-a", "acct", "westus", "127.0.0.1:4599")
	if err != nil || keySame != keyA {
		t.Fatalf("same account key: %v", err)
	}
	keyB, err := st.UpsertStorageAccount("sub-b", "rg-b", "acct", "eastus", "127.0.0.1:4599")
	if err != nil || keyB == "" || keyB == keyA {
		t.Fatalf("second account reused a key: %v", err)
	}

	if _, _, _, ok, err := st.GetStorageAccountByName("acct"); err != nil || ok {
		t.Fatalf("ambiguous account lookup ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.GetStorageAccountKey("acct"); err != nil || ok {
		t.Fatalf("ambiguous key lookup ok=%v err=%v", ok, err)
	}
	got, ok, err := st.GetStorageAccountKeyIn("sub-a", "rg-a", "acct")
	if err != nil || !ok || got != keyA {
		t.Fatalf("scoped key A: %q %v %v", got, ok, err)
	}
	got, ok, err = st.GetStorageAccountKeyIn("sub-b", "rg-b", "acct")
	if err != nil || !ok || got != keyB {
		t.Fatalf("scoped key B: %q %v %v", got, ok, err)
	}
	if _, ok, err := st.GetStorageAccountKeyIn("sub-a", "rg-other", "acct"); err != nil || ok {
		t.Fatalf("wrong resource group ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.GetStorageAccountKey("missing"); err != nil || ok {
		t.Fatal("missing key")
	}

	only, err := st.UpsertStorageAccount("sub-a", "rg-a", "only", "eastus", "127.0.0.1:4599")
	if err != nil {
		t.Fatal(err)
	}
	sub, rg, _, ok, err := st.GetStorageAccountByName("only")
	if err != nil || !ok || sub != "sub-a" || rg != "rg-a" {
		t.Fatalf("unique account: %s %s %v %v", sub, rg, ok, err)
	}
	if got, ok, err := st.GetStorageAccountKey("only"); err != nil || !ok || got != only {
		t.Fatal("unique key")
	}

	if err := st.UpsertKeyVault("sub-a", "rg-a", "kv", "eastus"); err != nil {
		t.Fatal(err)
	}
	scope, ok, err := st.LookupKeyVaultScope("kv")
	if err != nil || !ok || scope == "" {
		t.Fatalf("single vault: %q %v %v", scope, ok, err)
	}
	if err := st.UpsertKeyVault("sub-b", "rg-b", "kv", "eastus"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.LookupKeyVaultScope("kv"); err != nil || ok {
		t.Fatalf("ambiguous vault ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.LookupKeyVaultScope("missing-kv"); err != nil || ok {
		t.Fatal("missing vault")
	}

	if err := st.UpsertAppConfig("sub-a", "rg-a", "cfg", "eastus"); err != nil {
		t.Fatal(err)
	}
	row, ok, err := st.GetAppConfigByName("cfg")
	if err != nil || !ok || row.SubscriptionID != "sub-a" {
		t.Fatalf("single store: %+v %v %v", row, ok, err)
	}
	if err := st.UpsertAppConfig("sub-b", "rg-b", "cfg", "eastus"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.GetAppConfigByName("cfg"); err != nil || ok {
		t.Fatalf("ambiguous store ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.GetAppConfigByName("missing-cfg"); err != nil || ok {
		t.Fatal("missing store")
	}
}

func TestNameTakenIgnoresTheSameRow(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if _, err := st.UpsertStorageAccount("sub-a", "rg-a", "acct", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	taken, err := st.StorageAccountNameTaken("sub-a", "rg-a", "acct")
	if err != nil || taken {
		t.Fatalf("same row taken=%v err=%v", taken, err)
	}
	taken, err = st.StorageAccountNameTaken("sub-b", "rg-a", "acct")
	if err != nil || !taken {
		t.Fatalf("other subscription taken=%v err=%v", taken, err)
	}
	if err := st.UpsertKeyVault("sub-a", "rg-a", "kv", "eastus"); err != nil {
		t.Fatal(err)
	}
	taken, err = st.KeyVaultNameTaken("sub-b", "rg-b", "kv")
	if err != nil || !taken {
		t.Fatalf("vault taken=%v err=%v", taken, err)
	}
	if err := st.UpsertAppConfig("sub-a", "rg-a", "cfg", "eastus"); err != nil {
		t.Fatal(err)
	}
	taken, err = st.AppConfigNameTaken("sub-a", "rg-b", "cfg")
	if err != nil || !taken {
		t.Fatalf("appconfig taken=%v err=%v", taken, err)
	}
}

func TestStorageAccountNameTakenHidesTheOtherKey(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	keyA, err := st.UpsertStorageAccount("sub-a", "rg-a", "acct", "eastus", "127.0.0.1:4599")
	if err != nil || keyA == "" {
		t.Fatal(err)
	}
	same, err := st.StorageAccountNameTaken("sub-a", "rg-a", "acct")
	if err != nil || same {
		t.Fatalf("same subscription and resource group taken=%v err=%v", same, err)
	}
	other, err := st.StorageAccountNameTaken("sub-b", "rg-b", "acct")
	if err != nil || !other {
		t.Fatalf("other subscription taken=%v err=%v", other, err)
	}
	keyB, err := st.UpsertStorageAccount("sub-b", "rg-b", "other", "eastus", "127.0.0.1:4599")
	if err != nil || keyB == "" || keyB == keyA {
		t.Fatalf("second account key: %v", err)
	}
	takenOther, err := st.StorageAccountNameTaken("sub-a", "rg-a", "other")
	if err != nil || !takenOther {
		t.Fatalf("other name taken=%v err=%v", takenOther, err)
	}

	got, ok, err := st.GetStorageAccountKeyIn("sub-a", "rg-a", "acct")
	if err != nil || !ok || got != keyA || got == keyB {
		t.Fatalf("subscription A key %q ok=%v err=%v", got, ok, err)
	}
	got, ok, err = st.GetStorageAccountKeyIn("sub-b", "rg-b", "other")
	if err != nil || !ok || got != keyB || got == keyA {
		t.Fatalf("subscription B key %q ok=%v err=%v", got, ok, err)
	}
	got, ok, err = st.GetStorageAccountKeyIn("sub-b", "rg-b", "acct")
	if err != nil || ok || got == keyA || got == keyB {
		t.Fatalf("other subscription name lookup %q ok=%v err=%v", got, ok, err)
	}
	got, ok, err = st.GetStorageAccountKeyIn("sub-a", "rg-a", "missing")
	if err != nil || ok || got == keyA || got == keyB {
		t.Fatalf("missing name %q ok=%v err=%v", got, ok, err)
	}
	got, ok, err = st.GetStorageAccountKey("missing")
	if err != nil || ok || got == keyA || got == keyB {
		t.Fatalf("missing unscoped key %q ok=%v err=%v", got, ok, err)
	}
}

func TestServiceBusNamespaceKeyDoesNotCrossSubscriptions(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	keyA, err := st.UpsertServiceBusNamespace("sub-a", "rg-a", "ns-home", "eastus")
	if err != nil || keyA == "" {
		t.Fatal(err)
	}
	again, err := st.UpsertServiceBusNamespace("sub-a", "rg-a", "ns-home", "westus")
	if err != nil || again != keyA {
		t.Fatalf("same namespace key: %v", err)
	}
	if _, err := st.UpsertServiceBusNamespace("sub-b", "rg-b", "ns-home", "eastus"); err == nil {
		t.Fatal("second subscription accepted a used namespace name")
	}
	got, ok, err := st.GetSBNamespaceKeyIn("sub-b", "rg-b", "ns-home")
	if err != nil || ok || got != "" {
		t.Fatalf("foreign key lookup ok=%v key=%q err=%v", ok, got, err)
	}
	got, ok, err = st.GetSBNamespaceKeyIn("sub-a", "rg-a", "ns-home")
	if err != nil || !ok || got != keyA {
		t.Fatalf("home key ok=%v key=%q err=%v", ok, got, err)
	}
}
