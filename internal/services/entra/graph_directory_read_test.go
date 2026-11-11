package entra_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const (
	seededLabAdminID = "11111111-1111-1111-1111-111111111111"
	seededLabUserID  = "22222222-2222-2222-2222-222222222222"
	seededGARoleID   = "88888888-8888-8888-8888-888888888888"
	seededAARoleID   = "99999999-9999-9999-9999-999999999999"
)

func TestDirectoryReadsRequireDirectoryRole(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)

	ownerID := "dddddddd-dddd-dddd-dddd-dddddddddddd"
	if err := st.UpsertRoleAssignment(authz.Assignment{
		ID:               "ra-owner-not-directory",
		Scope:            "/subscriptions/" + config.DefaultSubscriptionID,
		RoleDefinitionID: authz.RoleOwner,
		PrincipalID:      ownerID,
		PrincipalType:    "User",
	}); err != nil {
		t.Fatal(err)
	}
	aaOnly := "abababab-abab-abab-abab-abababababab"
	if err := st.AddDirectoryRoleMember(seededAARoleID, aaOnly); err != nil {
		t.Fatal(err)
	}

	user := authn.Principal{ID: seededLabUserID, Audiences: []string{authn.AudienceGraph}}
	admin := authn.Principal{ID: seededLabAdminID, Audiences: []string{authn.AudienceGraph}}
	appAdmin := authn.Principal{ID: aaOnly, Audiences: []string{authn.AudienceGraph}}
	owner := authn.Principal{ID: ownerID, Audiences: []string{authn.AudienceGraph}}

	denyList := []string{
		"/v1.0/users",
		"/beta/users",
		"/" + config.DefaultTenantID + "/users?api-version=1.6",
		"/common/users?api-version=1.6",
		"/organizations/users?api-version=1.6",
		"/" + config.DefaultTenantID + "/directoryRoles?api-version=1.6",
		"/v1.0/directoryRoles",
		"/beta/directoryRoles",
		"/v1.0/directoryRoles/" + seededGARoleID + "/members",
		"/beta/directoryRoles/" + seededGARoleID + "/members",
		"/v1.0/roleManagement/directory/roleDefinitions",
		"/v1.0/roleManagement/directory/roleAssignments",
		"/api/Users",
	}
	for _, path := range denyList {
		rec := graphAs(t, mux, user, http.MethodGet, path, "")
		if rec.Code != http.StatusForbidden || graphCode(t, rec) != "Authorization_RequestDenied" {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "lab-admin") || strings.Contains(rec.Body.String(), seededLabAdminID) || strings.Contains(rec.Body.String(), `"value"`) {
			t.Fatalf("%s listed the directory: %s", path, rec.Body.String())
		}
	}

	ownerRec := graphAs(t, mux, owner, http.MethodGet, "/v1.0/users", "")
	if ownerRec.Code != http.StatusForbidden || graphCode(t, ownerRec) != "Authorization_RequestDenied" {
		t.Fatalf("subscription Owner status=%d body=%s", ownerRec.Code, ownerRec.Body.String())
	}

	soap := graphAs(t, mux, user, http.MethodPost, "/provisioningwebservice.svc",
		`<s:Envelope><s:Body><ListUsers xmlns="http://provisioning.microsoftonline.com/"/></s:Body></s:Envelope>`)
	if soap.Code != http.StatusForbidden || strings.Contains(soap.Body.String(), "ListUsersResponse") || strings.Contains(soap.Body.String(), "lab-admin") || strings.Contains(soap.Body.String(), seededLabAdminID) {
		t.Fatalf("SOAP ListUsers status=%d body=%s", soap.Code, soap.Body.String())
	}
	soapLower := graphAs(t, mux, user, http.MethodPost, "/provisioningwebservice.svc",
		`<s:Envelope><s:Body><listusers/></s:Body></s:Envelope>`)
	if soapLower.Code != http.StatusForbidden || strings.Contains(soapLower.Body.String(), "lab-user@lab.local") || strings.Contains(soapLower.Body.String(), seededLabAdminID) {
		t.Fatalf("SOAP listusers status=%d body=%s", soapLower.Code, soapLower.Body.String())
	}
	company := graphAs(t, mux, user, http.MethodPost, "/provisioningwebservice.svc",
		`<s:Envelope><s:Body><GetCompanyInformation/></s:Body></s:Envelope>`)
	if company.Code != http.StatusOK || !strings.Contains(company.Body.String(), "ContextId") || strings.Contains(company.Body.String(), "lab-admin") {
		t.Fatalf("SOAP company status=%d body=%s", company.Code, company.Body.String())
	}

	self := graphAs(t, mux, user, http.MethodGet, "/v1.0/users/"+seededLabUserID, "")
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
	if strings.Contains(self.Body.String(), store.SeededLabUserPassword) || strings.Contains(self.Body.String(), store.SeededLabAdminPassword) || strings.Contains(self.Body.String(), "lab-admin") {
		t.Fatalf("self get leaked other users or password material: %s", self.Body.String())
	}
	upper := graphAs(t, mux, user, http.MethodGet, "/beta/users/"+strings.ToUpper(seededLabUserID), "")
	if upper.Code != http.StatusOK {
		t.Fatalf("uppercase self id %d %s", upper.Code, upper.Body.String())
	}

	other := graphAs(t, mux, user, http.MethodGet, "/v1.0/users/"+seededLabAdminID, "")
	if other.Code != http.StatusForbidden || graphCode(t, other) != "Authorization_RequestDenied" {
		t.Fatalf("other user %d %s", other.Code, other.Body.String())
	}
	if strings.Contains(other.Body.String(), "lab-admin@lab.local") {
		t.Fatalf("other user body %s", other.Body.String())
	}

	missing := graphAs(t, mux, user, http.MethodGet, "/v1.0/users/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "")
	if missing.Code != http.StatusForbidden || strings.Contains(missing.Body.String(), `"value"`) {
		t.Fatalf("missing user %d %s", missing.Code, missing.Body.String())
	}
	nonUUID := graphAs(t, mux, user, http.MethodGet, "/v1.0/users/not-a-uuid", "")
	if nonUUID.Code != http.StatusBadRequest || graphCode(t, nonUUID) != "Request_BadRequest" {
		t.Fatalf("non-uuid %d %s", nonUUID.Code, nonUUID.Body.String())
	}
	if strings.Contains(nonUUID.Body.String(), "lab-user@lab.local") || strings.Contains(nonUUID.Body.String(), `"value"`) {
		t.Fatalf("non-uuid treated as a user: %s", nonUUID.Body.String())
	}
	upn := graphAs(t, mux, user, http.MethodGet, "/v1.0/users/"+url.PathEscape("lab-user@lab.local"), "")
	if upn.Code != http.StatusBadRequest {
		t.Fatalf("own upn %d %s", upn.Code, upn.Body.String())
	}
	otherUPN := graphAs(t, mux, user, http.MethodGet, "/v1.0/users/"+url.PathEscape("lab-admin@lab.local"), "")
	if otherUPN.Code != http.StatusBadRequest || strings.Contains(otherUPN.Body.String(), "Lab Admin") {
		t.Fatalf("other upn %d %s", otherUPN.Code, otherUPN.Body.String())
	}
	nonGUIDPrincipal := graphAs(t, mux, authn.Principal{ID: "lab-user@lab.local", Audiences: []string{authn.AudienceGraph}}, http.MethodGet, "/v1.0/users/"+url.PathEscape("lab-user@lab.local"), "")
	if nonGUIDPrincipal.Code == http.StatusOK {
		t.Fatalf("non-guid principal treated as self: %s", nonGUIDPrincipal.Body.String())
	}

	for _, p := range []authn.Principal{admin, appAdmin} {
		listed := graphAs(t, mux, p, http.MethodGet, "/v1.0/users", "")
		if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "lab-admin@lab.local") || !strings.Contains(listed.Body.String(), "lab-user@lab.local") {
			t.Fatalf("directory role %s list %d %s", p.ID, listed.Code, listed.Body.String())
		}
	}
	adminGet := graphAs(t, mux, admin, http.MethodGet, "/v1.0/users/"+seededLabUserID, "")
	if adminGet.Code != http.StatusOK || !strings.Contains(adminGet.Body.String(), "lab-user@lab.local") {
		t.Fatalf("admin get other %d %s", adminGet.Code, adminGet.Body.String())
	}
	roles := graphAs(t, mux, admin, http.MethodGet, "/v1.0/directoryRoles", "")
	if roles.Code != http.StatusOK || !strings.Contains(roles.Body.String(), "Global Administrator") {
		t.Fatalf("admin roles %d %s", roles.Code, roles.Body.String())
	}
	members := graphAs(t, mux, admin, http.MethodGet, "/v1.0/directoryRoles/"+seededGARoleID+"/members", "")
	if members.Code != http.StatusOK || !strings.Contains(members.Body.String(), seededLabAdminID) {
		t.Fatalf("admin members %d %s", members.Code, members.Body.String())
	}

	auth := &authn.Authenticator{Tokens: st, JWT: svc}
	ropcUser := mintPassword(t, mux, "lab-user@lab.local", store.SeededLabUserPassword)
	ropcPrincipal, err := auth.AuthenticateToken(ropcUser)
	if err != nil {
		t.Fatal(err)
	}
	if ropcPrincipal.IsRoot {
		t.Fatal("ROPC user token is root")
	}
	ropcDeny := graphAs(t, mux, ropcPrincipal, http.MethodGet, "/v1.0/users", "")
	if ropcDeny.Code != http.StatusForbidden {
		t.Fatalf("ROPC user list %d %s", ropcDeny.Code, ropcDeny.Body.String())
	}
	ropcSelf := graphAs(t, mux, ropcPrincipal, http.MethodGet, "/v1.0/users/"+ropcPrincipal.ID, "")
	if ropcSelf.Code != http.StatusOK || !strings.Contains(ropcSelf.Body.String(), "lab-user@lab.local") || strings.Contains(ropcSelf.Body.String(), "password") {
		t.Fatalf("ROPC self %d %s", ropcSelf.Code, ropcSelf.Body.String())
	}
	ropcAdmin := mintPassword(t, mux, "lab-admin@lab.local", store.SeededLabAdminPassword)
	adminPrincipal, err := auth.AuthenticateToken(ropcAdmin)
	if err != nil {
		t.Fatal(err)
	}
	ropcList := graphAs(t, mux, adminPrincipal, http.MethodGet, "/beta/users", "")
	if ropcList.Code != http.StatusOK || !strings.Contains(ropcList.Body.String(), "lab-user@lab.local") {
		t.Fatalf("ROPC admin list %d %s", ropcList.Code, ropcList.Body.String())
	}
}

func graphAs(t *testing.T, mux http.Handler, p authn.Principal, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/soap+xml")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req.WithContext(authn.WithPrincipal(req.Context(), p)))
	return rec
}

func graphCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("graph error json: %v body=%s", err, rec.Body.String())
	}
	errObj, _ := body["error"].(map[string]any)
	code, _ := errObj["code"].(string)
	return code
}

func mintPassword(t *testing.T, mux http.Handler, username, password string) string {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", "https://graph.microsoft.com/.default")
	req := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("password grant %s %d %s", username, rec.Code, rec.Body.String())
	}
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("empty access token %#v", tok)
	}
	return access
}
