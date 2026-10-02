package entra

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestApplyODataSelectSkipAndRoleHelpers(t *testing.T) {
	items := []map[string]any{
		{"id": "1", "displayName": "a", "extra": "x"},
		{"id": "2", "displayName": "b", "extra": "y"},
		{"id": "3", "displayName": "c", "extra": "z"},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1.0/users?$top=1&$skiptoken=1&$select=id,displayName", nil)
	page, next, more := applyOData(req, items)
	if len(page) != 1 || page[0]["id"] != "2" || page[0]["extra"] != nil {
		t.Fatalf("page %#v", page)
	}
	if next != 2 || !more {
		t.Fatalf("next=%d more=%v", next, more)
	}
	over := httptest.NewRequest(http.MethodGet, "/v1.0/users?$skiptoken=99&$top=bad", nil)
	page, _, more = applyOData(over, items)
	if len(page) != 0 || more {
		t.Fatalf("over-skip %#v more=%v", page, more)
	}

	want := map[string]struct{}{"global administrator": {}, "application administrator": {}, "user administrator": {}, "privileged role administrator": {}}
	cases := []store.DirectoryRole{
		{DisplayName: "Global Administrator"},
		{TemplateID: globalAdministratorTemplateID},
		{TemplateID: applicationAdministratorTemplateID},
		{TemplateID: userAdministratorTemplateID},
		{TemplateID: privilegedRoleAdministratorTemplateID},
		{ID: seededGlobalAdministratorRoleID},
		{ID: seededApplicationAdministratorRoleID},
		{ID: seededUserAdministratorRoleID},
		{DisplayName: "Other", ID: "nope", TemplateID: "nope"},
	}
	for _, role := range cases[:len(cases)-1] {
		if !directoryRoleNameMatches(role, want) {
			t.Fatalf("expected match %#v", role)
		}
	}
	if directoryRoleNameMatches(cases[len(cases)-1], want) {
		t.Fatal("other role matched")
	}

	s := &Service{TenantID: "tenant"}
	if !s.isAppAdminRoleID(applicationAdministratorTemplateID) {
		t.Fatal("template app admin")
	}
	if !s.isAppAdminRoleID(seededApplicationAdministratorRoleID) {
		t.Fatal("seeded app admin")
	}

	if caClientExcluded(nil, "") {
		t.Fatal("empty client exclude")
	}
	cond := map[string]any{
		"applications": map[string]any{"excludeApplications": []any{"app-1", 1}},
		"userAgents":   []any{"Lab/"},
		"clientAppTypes": []any{"browser", "LabCustom/"},
	}
	if !caClientExcluded(cond, "app-1") {
		t.Fatal("exclude")
	}
	if caUserAgentAllowed(cond, "") {
		t.Fatal("empty ua denied")
	}
	if !caUserAgentAllowed(cond, "Lab/1.0") {
		t.Fatal("ua allow")
	}
	if nestedMap(nil, "x") == nil {
		t.Fatal("nested nil")
	}
	if len(stringList([]string{"a"})) != 1 {
		t.Fatal("stringList []string")
	}

	_, err := parseRSAPublicPEM([]byte("not-pem"))
	if err == nil {
		t.Fatal("bad pem")
	}
	_ = errPEM.Error()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})
	if _, err := parseRSAPublicPEM(pubPEM); err != nil {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey)})
	if _, err := parseRSAPublicPEM(pkcs1); err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if _, err := parseRSAPublicPEM(privPEM); err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if _, err := parseRSAPublicPEM(pkcs8PEM); err != nil {
		t.Fatal(err)
	}
}
