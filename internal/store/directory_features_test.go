package store_test

import (
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestMatchFICExpressionAndExactSubject(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	appObj := "55555555-5555-5555-5555-555555555555"
	issuer := "https://token.actions.githubusercontent.com"
	aud := "api://AzureADTokenExchange"
	if err := st.EnsureRoot("tenant", "sub", "root"); err != nil {
		t.Fatal(err)
	}

	if _, err := st.CreateFIC(appObj, "exact", issuer, "repo:acme/app", []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	f, ok, err := st.FindFIC(issuer, "repo:acme/app", aud)
	if err != nil || !ok || f.Name != "exact" {
		t.Fatalf("exact: ok=%v err=%v %#v", ok, err, f)
	}

	expr := `{"value":"claims['sub'] matches 'repo:acme/*' and claims['repository_id'] eq '99'","languageVersion":1}`
	if _, err := st.CreateFIC(appObj, "flex", issuer, "", []string{aud}, expr); err != nil {
		t.Fatal(err)
	}
	f, ok, err = st.MatchFIC(issuer, aud, map[string]any{"sub": "repo:acme/tools", "repository_id": "99"})
	if err != nil || !ok || f.Name != "flex" {
		t.Fatalf("expression match: ok=%v err=%v %#v", ok, err, f)
	}
	if _, ok, err = st.MatchFIC(issuer, aud, map[string]any{"sub": "repo:other/tools", "repository_id": "99"}); err != nil || ok {
		t.Fatalf("wrong sub: ok=%v err=%v", ok, err)
	}
	if !store.EvaluateClaimsMatchingExpression(`claims['sub'] eq 'abc'`, map[string]any{"sub": "abc"}) {
		t.Fatal("eq should match")
	}
}

func TestAppConfigSnapshotKVFrozen(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	if err := st.UpsertAppConfig("sub", "rg", "cfg", "eastus"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAppConfigKV("cfg", "k", "", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAppConfigKV("cfg", "k", "prod", "p1"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAppConfigSnapshot("cfg", "s1", "ready"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAppConfigKV("cfg", "k", "", "v2"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListAppConfigSnapshotKV("cfg", "s1", "")
	if err != nil {
		t.Fatal(err)
	}
	foundV1 := false
	for _, row := range rows {
		if row.Key == "k" && row.Label == "" && row.Value == "v1" {
			foundV1 = true
		}
		if row.Value == "v2" {
			t.Fatalf("snapshot mutated: %#v", rows)
		}
	}
	if !foundV1 {
		t.Fatalf("missing captured kv: %#v", rows)
	}
	labeled, err := st.ListAppConfigSnapshotKV("cfg", "s1", "prod")
	if err != nil || len(labeled) != 1 || labeled[0].Value != "p1" {
		t.Fatalf("label filter: %#v %v", labeled, err)
	}
	snaps, err := st.ListAppConfigSnapshots("cfg")
	if err != nil || len(snaps) != 1 || snaps[0].Name != "s1" {
		t.Fatalf("list: %#v %v", snaps, err)
	}
}
