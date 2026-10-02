package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestDirectorySeedListsAndMutations(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	tenant := config.DefaultTenantID
	if err := st.EnsureRoot(tenant, config.DefaultSubscriptionID, "root"); err != nil {
		t.Fatal(err)
	}

	users, err := st.ListDirectoryUsers(tenant)
	if err != nil || len(users) < 2 {
		t.Fatalf("users: %v %v", users, err)
	}
	admin, ok, err := st.GetDirectoryUser("11111111-1111-1111-1111-111111111111")
	if err != nil || !ok || admin.UserPrincipalName == "" {
		t.Fatalf("get admin: %#v ok=%v err=%v", admin, ok, err)
	}
	byUPN, ok, err := st.GetDirectoryUser("lab-admin@lab.local")
	if err != nil || !ok || byUPN.ID != admin.ID {
		t.Fatalf("get by upn: %#v ok=%v err=%v", byUPN, ok, err)
	}
	if _, ok, err = st.GetDirectoryUser("missing-user"); err != nil || ok {
		t.Fatal("missing user")
	}
	if err := st.PatchDirectoryUser(admin.ID, "Security", "Lead"); err != nil {
		t.Fatal(err)
	}
	patched, ok, err := st.GetDirectoryUser(admin.ID)
	if err != nil || !ok || patched.Department != "Security" || patched.JobTitle != "Lead" {
		t.Fatalf("patched: %#v", patched)
	}
	if err := st.PatchDirectoryUser(admin.ID, "", ""); err != nil {
		t.Fatal(err)
	}
	keep, _, _ := st.GetDirectoryUser(admin.ID)
	if keep.Department != "Security" || keep.JobTitle != "Lead" {
		t.Fatalf("empty patch cleared fields: %#v", keep)
	}

	hash := store.HashUserPassword("NewPass!1")
	if err := st.SetUserPasswordHash(admin.ID, hash); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserPasswordHash("missing-user", hash); err == nil {
		t.Fatal("expected set hash missing user")
	}
	match, err := st.UserPasswordMatches(admin.ID, hash)
	if err != nil || !match {
		t.Fatalf("match: %v %v", match, err)
	}
	match, err = st.UserPasswordMatches(admin.ID, store.HashUserPassword("wrong"))
	if err != nil || match {
		t.Fatal("wrong password matched")
	}
	match, err = st.UserPasswordMatches(admin.ID, "")
	if err != nil || match {
		t.Fatal("empty hash matched")
	}
	match, err = st.UserPasswordMatches("missing-user", hash)
	if err != nil || match {
		t.Fatal("missing user password")
	}

	groups, err := st.ListDirectoryGroups(tenant)
	if err != nil || len(groups) < 2 {
		t.Fatalf("groups: %v %v", groups, err)
	}
	g, ok, err := st.GetDirectoryGroup("33333333-3333-3333-3333-333333333333")
	if err != nil || !ok || !g.SecurityEnabled {
		t.Fatalf("group: %#v ok=%v err=%v", g, ok, err)
	}
	if _, ok, err = st.GetDirectoryGroup("missing-group"); err != nil || ok {
		t.Fatal("missing group")
	}
	if err := st.UpdateGroupRule(g.ID, `user.department -eq "Security"`, "On"); err != nil {
		t.Fatal(err)
	}
	g2, _, _ := st.GetDirectoryGroup(g.ID)
	if g2.MembershipRule == "" || g2.MembershipRuleProcessingState != "On" {
		t.Fatalf("rule: %#v", g2)
	}
	if err := st.AddGroupMember(g.ID, "22222222-2222-2222-2222-222222222222", ""); err != nil {
		t.Fatal(err)
	}
	ids, types, err := st.ListGroupMembers(g.ID)
	if err != nil || len(ids) < 2 || len(types) != len(ids) {
		t.Fatalf("members: %v %v %v", ids, types, err)
	}

	sps, err := st.ListServicePrincipals(tenant)
	if err != nil || len(sps) < 1 {
		t.Fatalf("sps: %v %v", sps, err)
	}
	sp, ok, err := st.GetServicePrincipal("77777777-7777-7777-7777-777777777777")
	if err != nil || !ok || sp.AppID == "" {
		t.Fatalf("sp: %#v", sp)
	}
	spByApp, ok, err := st.GetServicePrincipal("66666666-6666-6666-6666-666666666666")
	if err != nil || !ok || spByApp.ID != sp.ID {
		t.Fatalf("sp by app: %#v", spByApp)
	}
	if _, ok, err = st.GetServicePrincipal("missing-sp"); err != nil || ok {
		t.Fatal("missing sp")
	}
	_, err = st.CreateServicePrincipal(tenant, "", "x")
	if err == nil {
		t.Fatal("empty appId")
	}
	_, err = st.CreateServicePrincipal(tenant, sp.AppID, "dup")
	if !errors.Is(err, store.ErrServicePrincipalExists) {
		t.Fatalf("dup sp: %v", err)
	}
	created, err := st.CreateServicePrincipal(tenant, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "New SP")
	if err != nil || created.ID == "" || created.AppID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("create sp: %#v %v", created, err)
	}

	if err := st.PutUnifiedRoleAssignment("", "22222222-2222-2222-2222-222222222222", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", ""); err != nil {
		t.Fatal(err)
	}
	uras, err := st.ListUnifiedRoleAssignments()
	if err != nil || len(uras) < 2 {
		t.Fatalf("uras: %v %v", uras, err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB().Exec(`INSERT INTO entra_devices (id, tenant_id, display_name, device_id, operating_system, created_at)
VALUES (?,?,?,?,?,?)`, "d1111111-1111-1111-1111-111111111111", tenant, "Lab Laptop", "device-lab-1", "Windows", now); err != nil {
		t.Fatal(err)
	}
	devices, err := st.ListDevices(tenant)
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices: %v %v", devices, err)
	}
	dev, ok, err := st.GetDevice("d1111111-1111-1111-1111-111111111111")
	if err != nil || !ok || dev.DeviceID != "device-lab-1" {
		t.Fatalf("get device: %#v", dev)
	}
	dev2, ok, err := st.GetDevice("device-lab-1")
	if err != nil || !ok || dev2.ID != dev.ID {
		t.Fatalf("get by device id: %#v", dev2)
	}
	if _, ok, err = st.GetDevice("missing-device"); err != nil || ok {
		t.Fatal("missing device")
	}
	if err := st.PatchDevice(dev.ID, "Renamed Laptop"); err != nil {
		t.Fatal(err)
	}
	if err := st.PatchDevice(dev.ID, ""); err != nil {
		t.Fatal(err)
	}
	renamed, _, _ := st.GetDevice(dev.ID)
	if renamed.DisplayName != "Renamed Laptop" {
		t.Fatalf("rename: %#v", renamed)
	}

	roles, err := st.ListDirectoryRoles(tenant)
	if err != nil || len(roles) < 3 {
		t.Fatalf("roles: %v %v", roles, err)
	}
	ga := "88888888-8888-8888-8888-888888888888"
	members, err := st.ListDirectoryRoleMembers(ga)
	if err != nil || len(members) < 1 {
		t.Fatalf("role members: %v %v", members, err)
	}
	if err := st.AddDirectoryRoleMember(ga, "22222222-2222-2222-2222-222222222222"); err != nil {
		t.Fatal(err)
	}

	appObj := "55555555-5555-5555-5555-555555555555"
	if err := st.AddOwner(appObj, admin.ID, ""); err != nil {
		t.Fatal(err)
	}
	owners, err := st.ListOwners(appObj)
	if err != nil || len(owners) != 1 || owners[0] != admin.ID {
		t.Fatalf("owners: %v %v", owners, err)
	}

	if _, err := st.CreateFIC(appObj, "cov-fic", "https://issuer.example", "sub:cov", nil, ""); err != nil {
		t.Fatal(err)
	}
	fics, err := st.ListFICs(appObj)
	if err != nil || len(fics) < 1 {
		t.Fatalf("fics: %v %v", fics, err)
	}

	polID, err := st.UpsertCAPolicy("", "Block Legacy", `{"grantControls":{"builtInControls":["block"]}}`, true)
	if err != nil || polID == "" {
		t.Fatal(err)
	}
	if _, err := st.UpsertCAPolicy(polID, "Block Legacy", `not-json`, false); err != nil {
		t.Fatal(err)
	}
	pols, err := st.ListCAPolicies()
	if err != nil || len(pols) != 1 {
		t.Fatalf("ca: %v %v", pols, err)
	}
	if pols[0]["state"] != "disabled" {
		t.Fatalf("ca state: %#v", pols[0])
	}

	secret := store.RandomToken(8)
	if len(secret) < 8 {
		t.Fatalf("token len %d", len(secret))
	}
	if store.HintFromSecret("ab") != "ab" || store.HintFromSecret("abcdef") != "abc" {
		t.Fatal("hint")
	}
	if store.NormalizeAppIdFilter("applications(appId='client-1')") != "client-1" {
		t.Fatal("normalize filter")
	}
	if store.NormalizeAppIdFilter("plain") != "plain" {
		t.Fatal("normalize plain")
	}
	pwID, err := st.AddPassword(appObj, "application", "cov", store.HashUserPassword(secret), store.HintFromSecret(secret))
	if err != nil || pwID == "" {
		t.Fatal(err)
	}
	exists, err := st.PasswordHashExists([]string{appObj, "", appObj}, store.HashUserPassword(secret))
	if err != nil || !exists {
		t.Fatalf("password exists: %v %v", exists, err)
	}
	exists, err = st.PasswordHashExists(nil, store.HashUserPassword(secret))
	if err != nil || exists {
		t.Fatal("empty ids")
	}
	exists, err = st.PasswordHashExists([]string{appObj}, "")
	if err != nil || exists {
		t.Fatal("empty hash")
	}
	exists, err = st.PasswordHashExists([]string{"other"}, store.HashUserPassword(secret))
	if err != nil || exists {
		t.Fatal("wrong resource")
	}

	n, err := st.CountKeyCredentials(appObj)
	if err != nil || n != 0 {
		t.Fatalf("key count: %d %v", n, err)
	}
	kid, err := st.AddKeyCredential(appObj, "application", "-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----", "", "")
	if err != nil || kid == "" {
		t.Fatal(err)
	}
	n, err = st.CountKeyCredentials(appObj)
	if err != nil || n != 1 {
		t.Fatalf("key count after: %d %v", n, err)
	}
	pems, err := st.ListKeyPEMs(appObj)
	if err != nil || len(pems) != 1 || !strings.Contains(pems[0], "PUBLIC KEY") {
		t.Fatalf("pems: %v %v", pems, err)
	}

	if _, err := st.DB().Exec(`INSERT INTO entra_app_role_assignments (id, principal_id, resource_id, app_role_id) VALUES (?,?,?,?)`,
		"ara-1", admin.ID, sp.ID, "00000000-0000-0000-0000-000000000000"); err != nil {
		t.Fatal(err)
	}
	aras, err := st.ListAppRoleAssignedTo(sp.ID)
	if err != nil || len(aras) != 1 {
		t.Fatalf("ara: %v %v", aras, err)
	}

	exp := time.Now().UTC().Add(time.Hour)
	if err := st.PutRefreshToken("rt-hash", admin.ID, "https://graph.microsoft.com", exp); err != nil {
		t.Fatal(err)
	}
	pid, aud, ok, err := st.LookupRefreshToken("rt-hash", time.Now().UTC())
	if err != nil || !ok || pid != admin.ID || aud != "https://graph.microsoft.com" {
		t.Fatalf("refresh: %q %q %v %v", pid, aud, ok, err)
	}
	_, _, ok, err = st.LookupRefreshToken("rt-hash", time.Now().UTC().Add(2*time.Hour))
	if err != nil || ok {
		t.Fatal("expired refresh")
	}
	_, _, ok, err = st.LookupRefreshToken("missing", time.Now().UTC())
	if err != nil || ok {
		t.Fatal("missing refresh")
	}

	if err := st.PutDeviceCode("dev-code-1", "ABCD", exp); err != nil {
		t.Fatal(err)
	}
	okApprove, err := st.ApproveDeviceCode("", admin.ID, time.Now().UTC())
	if err != nil || okApprove {
		t.Fatal("empty user code approve")
	}
	okApprove, err = st.ApproveDeviceCode("abcd", admin.ID, time.Now().UTC())
	if err != nil || !okApprove {
		t.Fatalf("approve: %v %v", okApprove, err)
	}
	pid, approved, ok, err := st.LookupDeviceCode("dev-code-1", time.Now().UTC())
	if err != nil || !ok || !approved || pid != admin.ID {
		t.Fatalf("device code: %q %v %v %v", pid, approved, ok, err)
	}
	_, _, ok, err = st.LookupDeviceCode("missing", time.Now().UTC())
	if err != nil || ok {
		t.Fatal("missing device code")
	}

	objID, appID, dn, ok, err := st.ResolveEntraApp(tenant, "66666666-6666-6666-6666-666666666666")
	if err != nil || !ok || objID != appObj || appID == "" || dn == "" {
		t.Fatalf("resolve: %q %q %q %v %v", objID, appID, dn, ok, err)
	}
	_, _, _, ok, err = st.ResolveEntraApp(tenant, "missing-app")
	if err != nil || ok {
		t.Fatal("resolve missing")
	}
}

func TestSubscriptionsManagementGroupsAndDiagnostics(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	tenant := "tenant-cov"
	if err := st.EnsureRoot(tenant, "sub-cov", "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSubscription("", "x", "", tenant); err == nil {
		t.Fatal("empty sub id")
	}
	if err := st.PutSubscription("sub-extra", "", "", tenant); err != nil {
		t.Fatal(err)
	}
	all, err := st.ListSubscriptions()
	if err != nil || len(all) < 2 {
		t.Fatalf("list subs: %v %v", all, err)
	}
	scoped, err := st.ListSubscriptionsForTenant(tenant)
	if err != nil || len(scoped) < 2 {
		t.Fatalf("tenant subs: %v %v", scoped, err)
	}
	empty, err := st.ListSubscriptionsForTenant("no-such-tenant")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty tenant: %v %v", empty, err)
	}

	mgs, err := st.ListManagementGroups()
	if err != nil || len(mgs) < 1 {
		t.Fatalf("mgs: %v %v", mgs, err)
	}
	if err := st.PutManagementGroup("", "x", tenant, ""); err == nil {
		t.Fatal("empty mg id")
	}
	if err := st.PutManagementGroup("mg-child", "Child MG", tenant, store.SeededManagementGroupID); err != nil {
		t.Fatal(err)
	}
	children, err := st.ListChildManagementGroups(store.SeededManagementGroupID, tenant)
	if err != nil || len(children) != 1 || children[0]["id"] != "mg-child" {
		t.Fatalf("children: %v %v", children, err)
	}
	none, err := st.ListChildManagementGroups("", tenant)
	if err != nil || len(none) != 0 {
		t.Fatalf("empty parent: %v %v", none, err)
	}

	if err := st.UpsertARGResource("arg-1", "resources", "microsoft.storage/storageaccounts", "sa1", "sub-cov", "rg", tenant, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertARGResource("arg-1", "resources", "microsoft.storage/storageaccounts", "sa1", "sub-cov", "rg", tenant, `{"sku":"Standard"}`); err != nil {
		t.Fatal(err)
	}
	args, err := st.ListARGResources("resources", "microsoft.storage/storageaccounts")
	if err != nil || len(args) != 1 {
		t.Fatalf("arg: %v %v", args, err)
	}
	allArgs, err := st.ListARGResources("", "")
	if err != nil || len(allArgs) != 1 {
		t.Fatalf("all arg: %v %v", allArgs, err)
	}

	if err := st.InsertLogAnalyticsRow("ws", "AzureActivity", map[string]any{"OperationName": "write"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDiagnosticSetting("ds-1", "/subscriptions/sub-cov", "diag", "ws", ""); err != nil {
		t.Fatal(err)
	}
	ds, ok, err := st.GetDiagnosticSetting("ds-1")
	if err != nil || !ok || ds["name"] != "diag" {
		t.Fatalf("get ds: %#v %v %v", ds, ok, err)
	}
	_, ok, err = st.GetDiagnosticSetting("missing")
	if err != nil || ok {
		t.Fatal("missing ds")
	}
	list, err := st.ListDiagnosticSettings("/subscriptions/sub-cov")
	if err != nil || len(list) != 1 {
		t.Fatalf("list ds: %v %v", list, err)
	}
	allDS, err := st.ListDiagnosticSettings("")
	if err != nil || len(allDS) < 1 {
		t.Fatalf("all ds: %v %v", allDS, err)
	}
	if err := st.DeleteDiagnosticSetting("ds-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteDiagnosticSetting("ds-1"); err == nil {
		t.Fatal("second delete")
	}
}

func TestACRBlobsManifestsAndLookupHelpers(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	uploadID, err := st.CreateACRUpload("repo/app")
	if err != nil || uploadID == "" {
		t.Fatal(err)
	}
	ok, err := st.ACRUploadExists(uploadID)
	if err != nil || !ok {
		t.Fatal(err)
	}
	ok, err = st.ACRUploadExists("missing")
	if err != nil || ok {
		t.Fatal("missing upload")
	}
	if err := st.FinishACRUpload(uploadID, "sha256:deadbeef", []byte("blob"), ""); err != nil {
		t.Fatal(err)
	}
	ok, err = st.ACRUploadExists(uploadID)
	if err != nil || ok {
		t.Fatal("upload should be gone")
	}
	content, ct, ok, err := st.GetACRBlob("sha256:deadbeef")
	if err != nil || !ok || string(content) != "blob" || ct != "application/octet-stream" {
		t.Fatalf("blob: %q %q %v %v", content, ct, ok, err)
	}
	_, _, ok, err = st.GetACRBlob("missing")
	if err != nil || ok {
		t.Fatal("missing blob")
	}
	if err := st.PutACRBlob("sha256:cafe", []byte("x"), "application/custom"); err != nil {
		t.Fatal(err)
	}
	content, ct, ok, err = st.GetACRBlob("sha256:cafe")
	if err != nil || !ok || string(content) != "x" || ct != "application/custom" {
		t.Fatalf("put blob: %q %q", content, ct)
	}
	if err := st.PutACRManifest("repo/app", "latest", "sha256:deadbeef", []byte(`{"schemaVersion":2}`), ""); err != nil {
		t.Fatal(err)
	}
	man, dig, mt, ok, err := st.GetACRManifest("repo/app", "latest")
	if err != nil || !ok || dig != "sha256:deadbeef" || !strings.Contains(string(man), "schemaVersion") || mt == "" {
		t.Fatalf("manifest: %q %q %q %v %v", man, dig, mt, ok, err)
	}
	_, _, _, ok, err = st.GetACRManifest("repo/app", "missing")
	if err != nil || ok {
		t.Fatal("missing manifest")
	}

	if store.EventHubNamespaceKey("s", "r", "n") == "" {
		t.Fatal("eh key")
	}
	if !store.IsNamedLogAnalyticsTable(store.LogTableAzureActivity) {
		t.Fatal("named table")
	}
	if store.IsNamedLogAnalyticsTable("Nope") {
		t.Fatal("unknown table")
	}

	if _, err := st.UpsertStorageAccount("sub", "rg", "sa1", "eastus", "127.0.0.1:4599"); err != nil {
		t.Fatal(err)
	}
	sas, err := st.ListStorageAccountsInSubscription("sub")
	if err != nil || len(sas) != 1 || sas[0].Name != "sa1" {
		t.Fatalf("list sa: %v %v", sas, err)
	}
	if err := st.UpsertKeyVault("sub", "rg", "kv1", "eastus"); err != nil {
		t.Fatal(err)
	}
	scope, ok, err := st.LookupKeyVaultScope("kv1")
	if err != nil || !ok || !strings.Contains(scope, "/vaults/kv1") {
		t.Fatalf("kv scope: %q %v %v", scope, ok, err)
	}
	_, ok, err = st.LookupKeyVaultScope("missing")
	if err != nil || ok {
		t.Fatal("missing kv scope")
	}
	if _, err := st.UpsertServiceBusNamespace("sub", "rg", "sbns", "eastus"); err != nil {
		t.Fatal(err)
	}
	sub, rg, loc, ok, err := st.GetServiceBusNamespaceByName("sbns")
	if err != nil || !ok || sub != "sub" || rg != "rg" || loc != "eastus" {
		t.Fatalf("sb by name: %v %v %v %v %v", sub, rg, loc, ok, err)
	}
	_, _, _, ok, err = st.GetServiceBusNamespaceByName("missing")
	if err != nil || ok {
		t.Fatal("missing sb")
	}
	if err := st.UpsertFunctionApp("sub", "rg", "fa1", "eastus", "ok"); err != nil {
		t.Fatal(err)
	}
	fas, err := st.ListFunctionAppsInSubscription("sub")
	if err != nil || len(fas) != 1 || fas[0].Name != "fa1" {
		t.Fatalf("fa list: %v %v", fas, err)
	}

	if err := st.UpsertSystemAssignedIdentity("sub", "rg", "sai", "eastus", "prin-sai", "client-sai"); err != nil {
		t.Fatal(err)
	}
	prin, client, ok, err := st.FindSystemAssignedByClientID("client-sai")
	if err != nil || !ok || prin != "prin-sai" || client != "client-sai" {
		t.Fatalf("sai by client: %v %v %v %v", prin, client, ok, err)
	}
	_, _, ok, err = st.FindSystemAssignedByClientID("missing")
	if err != nil || ok {
		t.Fatal("missing sai client")
	}
	clientOut, ok, err := st.FindSystemAssignedByPrincipalID("prin-sai")
	if err != nil || !ok || clientOut != "client-sai" {
		t.Fatalf("sai by prin: %q %v %v", clientOut, ok, err)
	}
	_, ok, err = st.FindSystemAssignedByPrincipalID("missing")
	if err != nil || ok {
		t.Fatal("missing sai prin")
	}

	kid, priv, err := st.EnsureOIDCLabSigningKey()
	if err != nil || kid == "" || priv == nil {
		t.Fatal(err)
	}
	kid2, priv2, err := st.EnsureOIDCLabSigningKey()
	if err != nil || kid2 != kid || priv2 == nil {
		t.Fatal(err)
	}

	if err := st.CreateTable("sa1", "t1"); err != nil {
		t.Fatal(err)
	}
	etag, created, err := st.InsertEntity("sa1", "t1", "p", "r", map[string]any{"Name": "Ada", "PartitionKey": "ignore"})
	if err != nil || !created || etag == "" {
		t.Fatalf("insert: %v %v %v", etag, created, err)
	}
	_, created, err = st.InsertEntity("sa1", "t1", "p", "r", map[string]any{"Name": "Bob"})
	if err != nil || created {
		t.Fatal("duplicate insert should fail closed")
	}
	rows, err := st.QueryEntities("sa1", "t1", "p", "", map[string]string{"Name": "Ada"}, 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("query prop: %v %v", rows, err)
	}
	rows, err = st.QueryEntities("sa1", "t1", "p", "", map[string]string{"Name": "Nope"}, 1)
	if err != nil || len(rows) != 0 {
		t.Fatalf("query miss: %v %v", rows, err)
	}
}
