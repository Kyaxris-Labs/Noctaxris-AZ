package store_test

import "testing"

func TestMatchFICLabIssuerIgnoresHost(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	appObj := "55555555-5555-5555-5555-555555555555"
	aud := "api://AzureADTokenExchange"
	sub := "repo:org/published"
	loop := "http://127.0.0.1:4599/_noctaxris-az/oidc-lab"
	pub := "http://203.0.113.10:59991/_noctaxris-az/oidc-lab"
	if _, err := st.CreateFIC(appObj, "loop", loop, sub, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	f, ok, err := st.MatchFIC(pub, aud, map[string]any{"sub": sub}, appObj)
	if err != nil || !ok || f.Name != "loop" {
		t.Fatalf("public iss vs loopback credential: ok=%v err=%v %#v", ok, err, f)
	}

	revSub := "repo:org/reverse"
	if _, err := st.CreateFIC(appObj, "public", pub, revSub, []string{aud}, ""); err != nil {
		t.Fatal(err)
	}
	f, ok, err = st.MatchFIC(loop, aud, map[string]any{"sub": revSub}, appObj)
	if err != nil || !ok || f.Name != "public" {
		t.Fatalf("loopback iss vs public credential: ok=%v err=%v %#v", ok, err, f)
	}

	if _, ok, err = st.MatchFIC("https://token.actions.githubusercontent.com", aud, map[string]any{"sub": sub}, appObj); err != nil || ok {
		t.Fatalf("unrelated issuer matched lab credential: ok=%v err=%v", ok, err)
	}
	if _, ok, err = st.MatchFIC("http://203.0.113.10:59991/_lab/oidc-lab", aud, map[string]any{"sub": sub}, appObj); err != nil || ok {
		t.Fatalf("other lab path matched: ok=%v err=%v", ok, err)
	}
}

func TestMatchFICStillExactForOtherIssuers(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	appObj := "55555555-5555-5555-5555-555555555555"
	issuer := "https://token.actions.githubusercontent.com"
	if _, err := st.CreateFIC(appObj, "gha", issuer, "repo:acme/app", []string{"api://AzureADTokenExchange"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.FindFIC(issuer, "repo:acme/app", "api://AzureADTokenExchange"); err != nil || !ok {
		t.Fatalf("exact issuer: ok=%v err=%v", ok, err)
	}
	if _, ok, err := st.FindFIC(issuer+"/", "repo:acme/app", "api://AzureADTokenExchange"); err != nil || ok {
		t.Fatalf("trailing slash on unrelated issuer: ok=%v err=%v", ok, err)
	}
}
