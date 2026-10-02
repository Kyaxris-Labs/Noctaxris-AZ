package entra_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestGroupOwnersRequireGroupsAdministrator(t *testing.T) {
	st := openStore(t)
	groupID := "33333333-3333-3333-3333-333333333333"
	ownerID := "22222222-2222-2222-2222-222222222222"
	body := `{"@odata.id":"https://graph.microsoft.com/v1.0/users/` + ownerID + `"}`

	aaMember := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	if _, err := st.DB().Exec(`INSERT OR IGNORE INTO entra_directory_role_members (role_id, member_id) VALUES (?,?)`,
		"99999999-9999-9999-9999-999999999999", aaMember); err != nil {
		t.Fatal(err)
	}

	low := graphServerAs(t, st, authn.Principal{ID: aaMember, Audiences: []string{authn.AudienceGraph}})
	denyReq, _ := http.NewRequest(http.MethodPost, low.URL+"/v1.0/groups/"+groupID+"/owners/$ref", strings.NewReader(body))
	denyReq.Header.Set("Content-Type", "application/json")
	denyRes, err := http.DefaultClient.Do(denyReq)
	if err != nil {
		t.Fatal(err)
	}
	denyBody := drain(t, denyRes)
	if denyRes.StatusCode != http.StatusForbidden {
		t.Fatalf("Application Administrator must not add group owners: %d %s", denyRes.StatusCode, denyBody)
	}

	groupsRole := "cccccccc-cccc-cccc-cccc-cccccccccccc"
	groupsAdmin := "dddddddd-dddd-dddd-dddd-dddddddddddd"
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB().Exec(`INSERT INTO entra_directory_roles (id, tenant_id, display_name, template_id, created_at) VALUES (?,?,?,?,?)`,
		groupsRole, config.DefaultTenantID, "Groups Administrator", "fdd7a751-b60b-444a-984c-02652fe8fa1c", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO entra_directory_role_members (role_id, member_id) VALUES (?,?)`,
		groupsRole, groupsAdmin); err != nil {
		t.Fatal(err)
	}

	okSrv := graphServerAs(t, st, authn.Principal{ID: groupsAdmin, Audiences: []string{authn.AudienceGraph}})
	okReq, _ := http.NewRequest(http.MethodPost, okSrv.URL+"/v1.0/groups/"+groupID+"/owners/$ref", strings.NewReader(body))
	okReq.Header.Set("Content-Type", "application/json")
	okRes, err := http.DefaultClient.Do(okReq)
	if err != nil {
		t.Fatal(err)
	}
	okBody := drain(t, okRes)
	if okRes.StatusCode != http.StatusNoContent {
		t.Fatalf("Groups Administrator must add group owners: %d %s", okRes.StatusCode, okBody)
	}
}
