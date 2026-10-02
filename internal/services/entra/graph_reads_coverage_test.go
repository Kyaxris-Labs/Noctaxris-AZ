package entra_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestGraphItemReadsPatchesRolesAndAAD(t *testing.T) {
	st := openStore(t)
	svc := &entra.Service{Store: st, TenantID: config.DefaultTenantID, PublicBase: "http://127.0.0.1:4599"}
	mux := http.NewServeMux()
	svc.Mount(mux)
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authn.WithPrincipal(r.Context(), authn.Principal{ID: "root", IsRoot: true})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB().Exec(`INSERT INTO entra_devices (id, tenant_id, display_name, device_id, operating_system, created_at)
VALUES (?,?,?,?,?,?)`, "d2222222-2222-2222-2222-222222222222", config.DefaultTenantID, "Cov Device", "dev-cov-1", "Linux", now); err != nil {
		t.Fatal(err)
	}

	getOK := func(path string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		wrap.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	user := getOK("/v1.0/users/11111111-1111-1111-1111-111111111111")
	if user["userPrincipalName"] == nil {
		t.Fatalf("user %#v", user)
	}
	rec := httptest.NewRecorder()
	wrap.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.0/users/missing-user", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing user %d", rec.Code)
	}

	group := getOK("/v1.0/groups/33333333-3333-3333-3333-333333333333")
	if group["displayName"] == nil {
		t.Fatalf("group %#v", group)
	}
	members := getOK("/v1.0/groups/33333333-3333-3333-3333-333333333333/members")
	if len(members["value"].([]any)) < 1 {
		t.Fatalf("members %#v", members)
	}

	sps := getOK("/v1.0/servicePrincipals")
	if len(sps["value"].([]any)) < 1 {
		t.Fatalf("sps %#v", sps)
	}
	sp := getOK("/v1.0/servicePrincipals/77777777-7777-7777-7777-777777777777")
	if sp["appId"] == nil {
		t.Fatalf("sp %#v", sp)
	}
	assigned := getOK("/v1.0/servicePrincipals/77777777-7777-7777-7777-777777777777/appRoleAssignedTo")
	if assigned["value"] == nil {
		t.Fatalf("assigned %#v", assigned)
	}

	devices := getOK("/v1.0/devices")
	if len(devices["value"].([]any)) < 1 {
		t.Fatalf("devices %#v", devices)
	}
	dev := getOK("/v1.0/devices/d2222222-2222-2222-2222-222222222222")
	if dev["deviceId"] != "dev-cov-1" {
		t.Fatalf("device %#v", dev)
	}

	roles := getOK("/v1.0/directoryRoles")
	if len(roles["value"].([]any)) < 1 {
		t.Fatalf("roles %#v", roles)
	}
	roleMembers := getOK("/v1.0/directoryRoles/88888888-8888-8888-8888-888888888888/members")
	if len(roleMembers["value"].([]any)) < 1 {
		t.Fatalf("role members %#v", roleMembers)
	}
	_ = getOK("/v1.0/roleManagement/directory/roleDefinitions")
	_ = getOK("/v1.0/roleManagement/directory/roleAssignments")
	empty1 := getOK("/v1.0/roleManagement/directory/roleEligibilityScheduleInstances")
	if len(empty1["value"].([]any)) != 0 {
		t.Fatalf("empty eligibility %#v", empty1)
	}
	empty2 := getOK("/v1.0/policies/roleManagementPolicyAssignments")
	if len(empty2["value"].([]any)) != 0 {
		t.Fatalf("empty policy %#v", empty2)
	}

	appObj := "55555555-5555-5555-5555-555555555555"
	if _, err := st.CreateFIC(appObj, "read-fic", "https://issuer.example", "sub:read", []string{"api://AzureADTokenExchange"}, ""); err != nil {
		t.Fatal(err)
	}
	fics := getOK("/v1.0/applications/" + appObj + "/federatedIdentityCredentials")
	if len(fics["value"].([]any)) < 1 {
		t.Fatalf("fics %#v", fics)
	}

	patchUser := httptest.NewRecorder()
	preq := httptest.NewRequest(http.MethodPatch, "/v1.0/users/11111111-1111-1111-1111-111111111111",
		strings.NewReader(`{"department":"Ops","jobTitle":"SRE"}`))
	preq.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(patchUser, preq)
	if patchUser.Code != http.StatusOK {
		t.Fatalf("patch user %d %s", patchUser.Code, patchUser.Body.String())
	}

	patchGroup := httptest.NewRecorder()
	greq := httptest.NewRequest(http.MethodPatch, "/v1.0/groups/33333333-3333-3333-3333-333333333333",
		strings.NewReader(`{"membershipRule":"user.department -eq \"Ops\"","membershipRuleProcessingState":"On"}`))
	greq.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(patchGroup, greq)
	if patchGroup.Code != http.StatusOK {
		t.Fatalf("patch group %d %s", patchGroup.Code, patchGroup.Body.String())
	}

	patchDev := httptest.NewRecorder()
	dreq := httptest.NewRequest(http.MethodPatch, "/v1.0/devices/d2222222-2222-2222-2222-222222222222",
		strings.NewReader(`{"displayName":"Renamed Cov Device"}`))
	dreq.Header.Set("Content-Type", "application/json")
	wrap.ServeHTTP(patchDev, dreq)
	if patchDev.Code != http.StatusOK {
		t.Fatalf("patch device %d %s", patchDev.Code, patchDev.Body.String())
	}

	tid := config.DefaultTenantID
	aadTenant := getOK("/" + tid + "/tenantDetails?api-version=1.6")
	if len(aadTenant["value"].([]any)) < 1 {
		t.Fatalf("aad tenant %#v", aadTenant)
	}
	aadRoles := getOK("/" + tid + "/directoryRoles?api-version=1.6")
	if len(aadRoles["value"].([]any)) < 1 {
		t.Fatalf("aad roles %#v", aadRoles)
	}

	jwks := httptest.NewRecorder()
	mux.ServeHTTP(jwks, httptest.NewRequest(http.MethodGet, "/_noctaxris-az/oidc-lab/keys", nil))
	if jwks.Code != http.StatusOK {
		t.Fatalf("jwks %d %s", jwks.Code, jwks.Body.String())
	}
	var keys map[string]any
	if err := json.Unmarshal(jwks.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys["keys"].([]any)) < 1 {
		t.Fatalf("jwks %#v", keys)
	}

	secret := addClientSecret(t, st, config.DefaultTenantID, "sp-verify-1")
	tokenBody := "grant_type=client_credentials&client_id=sp-verify-1&client_secret=" + secret + "&scope=https://graph.microsoft.com/.default"
	tokRec := httptest.NewRecorder()
	tokReq := httptest.NewRequest(http.MethodPost, "/"+config.DefaultTenantID+"/oauth2/v2.0/token", strings.NewReader(tokenBody))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("mint %d %s", tokRec.Code, tokRec.Body.String())
	}
	var tok map[string]any
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	access, _ := tok["access_token"].(string)
	pid, ok, err := svc.VerifyAccessToken(access, time.Now().UTC())
	if err != nil || !ok || pid == "" {
		t.Fatalf("verify: %q %v %v", pid, ok, err)
	}
	claims, ok, err := svc.VerifyAccessTokenClaims(access, time.Now().UTC())
	if err != nil || !ok || claims["aud"] == nil {
		t.Fatalf("verify claims: %#v %v %v", claims, ok, err)
	}
	_, ok, err = svc.VerifyAccessToken("not-a-jwt", time.Now().UTC())
	if err != nil || ok {
		t.Fatal("bad token should not verify")
	}

	_ = store.SeededLabAdminPassword
}
