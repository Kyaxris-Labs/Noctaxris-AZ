package entra_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
)

func TestGraphGroupMembersRequireDirectoryRole(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	const groupID = "33333333-3333-3333-3333-333333333333"
	if err := st.AddOwner(groupID, seededLabAdminID, "user"); err != nil {
		t.Fatal(err)
	}
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{
			ID:        seededLabUserID,
			Audiences: []string{authn.AudienceGraph},
		})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})

	for _, path := range []string{
		"/v1.0/groups/" + groupID + "/members",
		"/beta/groups/" + groupID + "/members",
		"/v1.0/groups/" + groupID + "/owners",
		"/beta/groups/" + groupID + "/owners",
		"/v1.0/applications/55555555-5555-5555-5555-555555555555/owners",
	} {
		rec := httptest.NewRecorder()
		wrap.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Authorization_RequestDenied") {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), seededLabAdminID) {
			t.Fatalf("%s returned another user: %s", path, rec.Body.String())
		}
	}

	self := httptest.NewRecorder()
	wrap.ServeHTTP(self, httptest.NewRequest(http.MethodGet, "/v1.0/users/"+seededLabUserID, nil))
	if self.Code != http.StatusOK {
		t.Fatalf("self get %d %s", self.Code, self.Body.String())
	}
	var selfBody map[string]any
	if err := json.Unmarshal(self.Body.Bytes(), &selfBody); err != nil {
		t.Fatal(err)
	}
	if selfBody["id"] != seededLabUserID || selfBody["userPrincipalName"] != "lab-user@lab.local" {
		t.Fatalf("self body %#v", selfBody)
	}
	if _, hasHash := selfBody["password_hash"]; hasHash {
		t.Fatalf("self get returned password_hash %#v", selfBody)
	}
	if _, hasProfile := selfBody["passwordProfile"]; hasProfile {
		t.Fatalf("self get returned passwordProfile %#v", selfBody)
	}
	if strings.Contains(self.Body.String(), seededLabAdminID) || strings.Contains(self.Body.String(), "lab-admin") {
		t.Fatalf("self get leaked another user: %s", self.Body.String())
	}
}
