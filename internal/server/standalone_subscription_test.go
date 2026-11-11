package server_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/server"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const standaloneSeedPath = "/_noctaxris-az/lab/subscriptions:seedStandalone"

func TestStandaloneSubscriptionDisabledIsNotFound(t *testing.T) {
	srv, cfg := standaloneServer(t, false)
	h := srv.Handler()
	for _, token := range []string{"", cfg.RootAccessToken} {
		req := httptest.NewRequest(http.MethodPost, standaloneSeedPath, strings.NewReader(`{"name":"home"}`))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("token set=%v status=%d body=%s", token != "", rec.Code, rec.Body.String())
		}
	}
}

func TestStandaloneSubscriptionSeedRootIsolationAndIdempotent(t *testing.T) {
	srv, cfg, st := standaloneServerStore(t, true)
	h := srv.Handler()

	if err := st.UpsertResourceGroup(cfg.SubscriptionID, "rg-lab", "eastus"); err != nil {
		t.Fatal(err)
	}

	denied := postStandalone(t, h, labAdminToken(t, h, cfg), []byte(`{"name":"home"}`))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-root status=%d body=%s", denied.Code, denied.Body.String())
	}

	first := postStandalone(t, h, cfg.RootAccessToken, []byte(`{"name":"home"}`))
	if first.Code != http.StatusOK {
		t.Fatalf("seed status=%d body=%s", first.Code, first.Body.String())
	}
	seeded := decodeSeed(t, first)
	if seeded.AccessToken == "" || seeded.AccessToken == cfg.RootAccessToken {
		t.Fatal("seed token missing or equal to root")
	}
	if seeded.SubscriptionID == cfg.SubscriptionID || seeded.SubscriptionID == cfg.TenantID {
		t.Fatalf("subscription id %s", seeded.SubscriptionID)
	}
	if strings.Contains(strings.ToLower(seeded.UserPrincipalName), "lab-admin") {
		t.Fatalf("upn %s", seeded.UserPrincipalName)
	}

	auth := &authn.Authenticator{RootClientID: cfg.RootClientID, RootAccessToken: cfg.RootAccessToken, Tokens: st}
	p, err := auth.AuthenticateToken(seeded.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	_, claims, err := authn.DecodeJWTUnverified(seeded.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if p.IsRoot || p.ID != seeded.UserID || !p.AllowsARM() {
		t.Fatalf("principal %+v", p)
	}
	if authn.ClaimString(claims, "aud") != authn.AudienceARM {
		t.Fatalf("aud %q", authn.ClaimString(claims, "aud"))
	}
	if authn.ClaimString(claims, "oid") != seeded.UserID {
		t.Fatalf("oid %q user %s", authn.ClaimString(claims, "oid"), seeded.UserID)
	}
	if authn.ClaimString(claims, "tid") != cfg.TenantID {
		t.Fatalf("tid %q", authn.ClaimString(claims, "tid"))
	}
	if authn.ClaimString(claims, "sub") != seeded.UserID || authn.ClaimString(claims, "appid") != seeded.UserID || authn.ClaimString(claims, "azp") != seeded.UserID {
		t.Fatalf("sub=%q appid=%q azp=%q", authn.ClaimString(claims, "sub"), authn.ClaimString(claims, "appid"), authn.ClaimString(claims, "azp"))
	}
	if authn.ClaimString(claims, "ver") != "2.0" {
		t.Fatalf("ver %q", authn.ClaimString(claims, "ver"))
	}
	if err := userHasDirectoryRole(st, seeded.UserID); err != nil {
		t.Fatal(err)
	}
	assignments, err := st.ListRoleAssignmentsByScopePrefix("/subscriptions/" + seeded.SubscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	var owned []authz.Assignment
	for _, a := range assignments {
		if a.PrincipalID == seeded.UserID {
			owned = append(owned, a)
		}
	}
	if len(owned) != 1 || owned[0].PrincipalType != "User" || owned[0].Scope != "/subscriptions/"+seeded.SubscriptionID {
		t.Fatalf("assignments %+v", owned)
	}
	if !strings.Contains(strings.ToLower(owned[0].RoleDefinitionID), "8e3af657-a8ff-443c-a75c-2fe8c4bcb635") {
		t.Fatalf("role %s", owned[0].RoleDefinitionID)
	}
	labAssignments, err := st.ListRoleAssignmentsByScopePrefix("/subscriptions/" + cfg.SubscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range labAssignments {
		if a.PrincipalID == seeded.UserID {
			t.Fatalf("lab assignment %+v", a)
		}
	}

	list := authedGET(t, h, "/subscriptions?api-version=2022-12-01", seeded.AccessToken)
	if list.Code != http.StatusOK {
		t.Fatalf("list %d %s", list.Code, list.Body.String())
	}
	var listed struct {
		Value []struct {
			SubscriptionID string `json:"subscriptionId"`
		} `json:"value"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Value) != 1 || listed.Value[0].SubscriptionID != seeded.SubscriptionID {
		t.Fatalf("visible %#v", listed.Value)
	}

	labGet := authedGET(t, h, "/subscriptions/"+cfg.SubscriptionID+"?api-version=2022-12-01", seeded.AccessToken)
	if labGet.Code != http.StatusForbidden {
		t.Fatalf("lab subscription get %d %s", labGet.Code, labGet.Body.String())
	}
	labRG := authedGET(t, h, "/subscriptions/"+cfg.SubscriptionID+"/resourceGroups/rg-lab?api-version=2022-12-01", seeded.AccessToken)
	if labRG.Code != http.StatusForbidden {
		t.Fatalf("lab resource group %d %s", labRG.Code, labRG.Body.String())
	}

	if err := st.UpsertResourceGroup(seeded.SubscriptionID, "rg-home", "eastus"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertStorageAccount(seeded.SubscriptionID, "rg-home", "standaloneacct", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	blob := authedGET(t, h, "/blob/standaloneacct/container/object", seeded.AccessToken)
	if blob.Code != http.StatusForbidden {
		t.Fatalf("blob data plane %d %s", blob.Code, blob.Body.String())
	}
	if err := st.UpsertKeyVault(seeded.SubscriptionID, "rg-home", "standalonevault", "eastus"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutSecret("standalonevault", "demo", "secret-value"); err != nil {
		t.Fatal(err)
	}
	secret := authedGET(t, h, "/keyvault/standalonevault/secrets/demo", seeded.AccessToken)
	if secret.Code == http.StatusOK || strings.Contains(secret.Body.String(), "secret-value") {
		t.Fatalf("key vault getSecret %d %s", secret.Code, secret.Body.String())
	}

	again := postStandalone(t, h, cfg.RootAccessToken, []byte(`{"name":"home"}`))
	second := decodeSeed(t, again)
	if second.AccessToken != seeded.AccessToken || second.SubscriptionID != seeded.SubscriptionID {
		t.Fatal("reseed rotated token or subscription")
	}

	otherRec := postStandalone(t, h, cfg.RootAccessToken, []byte(`{"name":"other"}`))
	other := decodeSeed(t, otherRec)
	if other.SubscriptionID == seeded.SubscriptionID || other.AccessToken == seeded.AccessToken {
		t.Fatal("second seed name reused the first subscription")
	}
}

type seedBody struct {
	SubscriptionID    string `json:"subscriptionId"`
	TenantID          string `json:"tenantId"`
	UserID            string `json:"userId"`
	UserPrincipalName string `json:"userPrincipalName"`
	AccessToken       string `json:"accessToken"`
}

func decodeSeed(t *testing.T, rec *httptest.ResponseRecorder) seedBody {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body seedBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func standaloneServer(t *testing.T, enabled bool) (*server.Server, config.Config) {
	t.Helper()
	srv, cfg, _ := standaloneServerStore(t, enabled)
	return srv, cfg
}

func standaloneServerStore(t *testing.T, enabled bool) (*server.Server, config.Config, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	key, err := store.LoadOrCreateMasterKey(filepath.Join(dir, "secrets", "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Config{
		ListenAddr:      "127.0.0.1:0",
		AMQPListenAddr:  "127.0.0.1:0",
		DataRoot:        filepath.Join(dir, "data"),
		RootClientID:    "root-client",
		RootAccessToken: "test-root-token",
		TenantID:        config.DefaultTenantID,
		SubscriptionID:  config.DefaultSubscriptionID,
		LabStandalone:   enabled,
	}
	if err := st.EnsureRoot(cfg.TenantID, cfg.SubscriptionID, cfg.RootClientID); err != nil {
		t.Fatal(err)
	}
	return server.New(cfg, st, nil), cfg, st
}

func postStandalone(t *testing.T, h http.Handler, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, standaloneSeedPath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func authedGET(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func labAdminToken(t *testing.T, h http.Handler, cfg config.Config) string {
	t.Helper()
	form := "grant_type=password&username=lab-admin@lab.local&password=" + url.QueryEscape(store.SeededLabAdminPassword) +
		"&scope=" + url.QueryEscape(authn.AudienceARM+"/.default")
	req := httptest.NewRequest(http.MethodPost, "/"+cfg.TenantID+"/oauth2/v2.0/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("lab admin token %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.AccessToken == "" || body.AccessToken == cfg.RootAccessToken {
		t.Fatal("lab admin token missing")
	}
	return body.AccessToken
}

func userHasDirectoryRole(st *store.Store, userID string) error {
	roles, err := st.ListDirectoryRoles(config.DefaultTenantID)
	if err != nil {
		return err
	}
	for _, role := range roles {
		members, err := st.ListDirectoryRoleMembers(role.ID)
		if err != nil {
			return err
		}
		for _, member := range members {
			if member == userID {
				return errDirectoryRole
			}
		}
	}
	rows, err := st.ListUnifiedRoleAssignments()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row["principalId"] == userID {
			return errDirectoryRole
		}
	}
	return nil
}

var errDirectoryRole = errors.New("user has a directory role")
