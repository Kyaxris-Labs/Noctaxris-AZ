package authn_test

import (
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestAudienceKindsPositiveNegativeBoundary(t *testing.T) {
	cases := []struct {
		name string
		aud  string
		check func(authn.Principal) bool
		want bool
	}{
		{"arm", authn.AudienceARM, authn.Principal.AllowsARM, true},
		{"arm-legacy", authn.AudienceARMLegacy, authn.Principal.AllowsARM, true},
		{"arm-slash", authn.AudienceARM + "/", authn.Principal.AllowsARM, true},
		{"graph-not-arm", authn.AudienceGraph, authn.Principal.AllowsARM, false},
		{"vault", authn.AudienceVault, authn.Principal.AllowsVault, true},
		{"vault-mixed", authn.AudienceVault, func(p authn.Principal) bool {
			p.Audiences = []string{authn.AudienceVault, authn.AudienceARM}
			return p.AllowsVault()
		}, false},
		{"servicebus", authn.AudienceServiceBus, authn.Principal.AllowsServiceBus, true},
		{"eventhubs", authn.AudienceEventHubs, authn.Principal.AllowsEventHubs, true},
		{"eventhubs-opaque", "", authn.Principal.AllowsEventHubs, true},
		{"eventgrid", authn.AudienceEventGrid, authn.Principal.AllowsEventGrid, true},
		{"appconfig", authn.AudienceAppConfig, authn.Principal.AllowsAppConfig, true},
		{"cognitive", authn.AudienceCognitive, authn.Principal.AllowsCognitive, true},
		{"communication", authn.AudienceCommunication, authn.Principal.AllowsCommunication, true},
		{"graph", authn.AudienceGraph, authn.Principal.AllowsGraph, true},
		{"graph-appid", authn.AudienceGraphAppID, authn.Principal.AllowsGraph, true},
		{"aadgraph", authn.AudienceAADGraph, authn.Principal.AllowsGraph, true},
		{"unknown", "https://example.invalid/", authn.Principal.AllowsARM, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := authn.Principal{ID: "sp", Audiences: nil}
			if tc.aud != "" {
				p.Audiences = []string{tc.aud}
			}
			if got := tc.check(p); got != tc.want {
				t.Fatalf("got=%v want=%v aud=%q", got, tc.want, tc.aud)
			}
		})
	}

	root := authn.Principal{ID: "root", IsRoot: true}
	if !root.AllowsARM() || !root.AllowsVault() || !root.AllowsEventHubs() {
		t.Fatal("root must allow data-plane audiences")
	}
	if authn.NormalizeAudience("  https://vault.azure.net/  ") != "https://vault.azure.net" {
		t.Fatal("normalize should trim space and slash")
	}
}

func TestClaimAudiencesEquivalenceAndClaimUnix(t *testing.T) {
	if got := authn.ClaimAudiences(nil); got != nil {
		t.Fatalf("nil claims => nil, got %#v", got)
	}
	if got := authn.ClaimAudiences(map[string]any{"aud": "  "}); got != nil {
		t.Fatalf("blank aud => nil, got %#v", got)
	}
	if got := authn.ClaimAudiences(map[string]any{"aud": authn.AudienceARM}); len(got) != 1 || got[0] != authn.AudienceARM {
		t.Fatalf("string aud=%#v", got)
	}
	if got := authn.ClaimAudiences(map[string]any{"aud": []any{authn.AudienceARM, 1, "  ", authn.AudienceVault}}); len(got) != 2 {
		t.Fatalf("array aud=%#v", got)
	}
	if got := authn.ClaimAudiences(map[string]any{"aud": 123}); got != nil {
		t.Fatalf("non-string aud=%#v", got)
	}

	if _, ok := authn.ClaimUnix(nil, "exp"); ok {
		t.Fatal("nil claims")
	}
	if v, ok := authn.ClaimUnix(map[string]any{"exp": float64(100)}, "exp"); !ok || v != 100 {
		t.Fatalf("float64 exp=%v ok=%v", v, ok)
	}
	if v, ok := authn.ClaimUnix(map[string]any{"exp": int64(100)}, "exp"); !ok || v != 100 {
		t.Fatalf("int64 exp=%v ok=%v", v, ok)
	}
	if v, ok := authn.ClaimUnix(map[string]any{"exp": int(100)}, "exp"); !ok || v != 100 {
		t.Fatalf("int exp=%v ok=%v", v, ok)
	}
	if _, ok := authn.ClaimUnix(map[string]any{"exp": "bad"}, "exp"); ok {
		t.Fatal("string exp must fail")
	}
	if authn.ClaimString(map[string]any{"iss": "  x  "}, "iss") != "x" {
		t.Fatal("ClaimString should trim")
	}
	if authn.PrincipalFromJWTClaims(map[string]any{"oid": "oid-1", "sub": "sub-1"}) != "oid-1" {
		t.Fatal("prefer oid")
	}
	if authn.PrincipalFromJWTClaims(map[string]any{"sub": "sub-1"}) != "sub-1" {
		t.Fatal("fallback sub")
	}
	if authn.PrincipalFromJWTClaims(map[string]any{"appid": "app-1"}) != "app-1" {
		t.Fatal("fallback appid")
	}
	if authn.PrincipalFromJWTClaims(nil) != "" {
		t.Fatal("nil claims")
	}
}
