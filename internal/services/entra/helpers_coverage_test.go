package entra

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestRequirePrincipalAndSegmentAfter(t *testing.T) {
	s := &Service{TenantID: "tenant"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.0/users", nil)
	if s.requirePrincipal(rec, req) {
		t.Fatal("unauth should fail")
	}
	rec = httptest.NewRecorder()
	req = req.WithContext(authn.WithPrincipal(req.Context(), authn.Principal{ID: "root", IsRoot: true}))
	if !s.requirePrincipal(rec, req) {
		t.Fatal("root should pass")
	}

	if segmentAfter("/v1.0/applications/abc-123/owners", "/applications/") != "abc-123" {
		t.Fatal("segment applications")
	}
	if segmentAfter("/v1.0/groups/g1/members", "/groups/") != "g1" {
		t.Fatal("segment groups")
	}
	if segmentAfter("/nope", "/applications/") != "" {
		t.Fatal("missing marker")
	}
	if got := encodeFICExpression(nil); got != "" {
		t.Fatalf("nil expr %q", got)
	}
	if got := encodeFICExpression([]byte(`{"value":"claims['sub'] eq 'x'","languageVersion":2}`)); got == "" {
		t.Fatal("object expr")
	}
	if got := encodeFICExpression([]byte(`"claims['sub'] eq 'y'"`)); got == "" {
		t.Fatal("string expr")
	}
	if !matchDirectoryRule(`user.department -eq "Ops"`, "user", "Ops", "", "") {
		t.Fatal("dept rule")
	}
	if !matchDirectoryRule(`user.jobTitle -eq 'SRE'`, "user", "", "SRE", "") {
		t.Fatal("title rule")
	}
	if !matchDirectoryRule(`device.displayName -eq "Laptop"`, "device", "", "", "Laptop") {
		t.Fatal("device rule")
	}
	if matchDirectoryRule(`servicePrincipal.displayName -eq "x"`, "user", "", "", "x") {
		t.Fatal("sp rule should fail")
	}
}
