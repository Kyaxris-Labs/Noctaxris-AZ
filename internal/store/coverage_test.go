package store_test

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestSealRoundtripAndMasterKeyPaths(t *testing.T) {
	var mk store.MasterKey
	for i := range mk {
		mk[i] = byte(i + 1)
	}
	sealed, err := store.Seal(mk, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := store.Unseal(mk, sealed)
	if err != nil || string(plain) != "hello" {
		t.Fatalf("unseal: %q %v", plain, err)
	}
	if _, err := store.Unseal(mk, []byte{1, 2}); err == nil {
		t.Fatal("expected short ciphertext error")
	}

	dir := t.TempDir()
	keyPath := dir + "/outside/master.key"
	key, err := store.LoadOrCreateMasterKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := store.LoadOrCreateMasterKey(keyPath)
	if err != nil || !bytes.Equal(key[:], key2[:]) {
		t.Fatalf("reload mismatch: %v", err)
	}

	dataRoot := dir + "/data"
	path, err := store.ResolveMasterKeyPath("", dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(path, "data-secrets") && !strings.Contains(path, "master.key") {
		t.Fatalf("default path %q", path)
	}
	under, err := store.MasterKeyPathUnderDataRoot(dataRoot+"/master.key", dataRoot)
	if err != nil || !under {
		t.Fatalf("under: %v %v", under, err)
	}
	if _, err := store.ResolveMasterKeyPath(dataRoot+"/master.key", dataRoot); err == nil {
		t.Fatal("expected refuse key under data root")
	}
	t.Setenv(store.EnvAllowMasterKeyInDataRoot, "1")
	if !store.AllowMasterKeyInDataRoot() {
		t.Fatal("allow flag")
	}
	path, err = store.ResolveMasterKeyPath("", dataRoot)
	if err != nil || !strings.HasSuffix(strings.ReplaceAll(path, "\\", "/"), "/data/master.key") {
		t.Fatalf("colocated path %q %v", path, err)
	}
	_ = store.DefaultMasterKeyPath(dataRoot)
}

func TestEnsureRootTokensAndKVSecretsKeys(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	if err := st.EnsureRoot("tenant", "sub", "root"); err != nil {
		t.Fatal(err)
	}
	dn, state, tid, ok, err := st.GetSubscription("sub")
	if err != nil || !ok || state != "Enabled" || tid != "tenant" || dn == "" {
		t.Fatalf("sub: %v %v %q %q %q", ok, err, dn, state, tid)
	}
	if st.DataRoot() == "" || len(st.Master()) != 32 {
		t.Fatal("master/data root")
	}
	_ = st.DB()

	hash := "abc"
	if err := st.PutAccessToken(hash, "p1", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	id, ok, err := st.LookupAccessToken(hash, time.Now().UTC())
	if err != nil || !ok || id != "p1" {
		t.Fatalf("lookup: %q %v %v", id, ok, err)
	}
	id, ok, err = st.LookupAccessToken(hash, time.Now().UTC().Add(2*time.Hour))
	if err != nil || ok {
		t.Fatalf("expired: %v %v %v", id, ok, err)
	}
	if err := st.PutAccessToken("noexp", "p2", time.Time{}); err != nil {
		t.Fatal(err)
	}
	id, ok, err = st.LookupAccessToken("noexp", time.Now().UTC())
	if err != nil || !ok || id != "p2" {
		t.Fatalf("noexp: %q %v %v", id, ok, err)
	}

	if err := st.UpsertKeyVault("sub", "rg", "kv", ""); err != nil {
		t.Fatal(err)
	}
	loc, ok, err := st.GetKeyVault("sub", "rg", "kv")
	if err != nil || !ok || loc != "eastus" {
		t.Fatalf("kv: %q %v %v", loc, ok, err)
	}
	exists, err := st.KeyVaultExists("kv")
	if err != nil || !exists {
		t.Fatal(err)
	}
	ver, err := st.PutSecret("kv", "s1", "v1")
	if err != nil || ver == "" {
		t.Fatal(err)
	}
	val, ver2, ok, err := st.GetSecret("kv", "s1")
	if err != nil || !ok || val != "v1" || ver2 != ver {
		t.Fatalf("get secret: %q %q %v %v", val, ver2, ok, err)
	}
	_, _, ok, err = st.GetSecret("kv", "missing")
	if err != nil || ok {
		t.Fatal("missing secret")
	}
	ok, err = st.SoftDeleteSecret("kv", "s1")
	if err != nil || !ok {
		t.Fatal(err)
	}
	_, _, ok, err = st.GetSecret("kv", "s1")
	if err != nil || ok {
		t.Fatal("deleted still present")
	}
	recVer, ok, err := st.RecoverSecret("kv", "s1")
	if err != nil || !ok || recVer != ver {
		t.Fatalf("recover: %q %v %v", recVer, ok, err)
	}
	ok, err = st.SoftDeleteSecret("kv", "missing")
	if err != nil || ok {
		t.Fatal("soft-delete missing")
	}
	_, ok, err = st.RecoverSecret("kv", "missing")
	if err != nil || ok {
		t.Fatal("recover missing")
	}

	kver, err := st.PutKey("kv", "k1", []byte("material"))
	if err != nil || kver == "" {
		t.Fatal(err)
	}
	mat, kver2, ok, err := st.GetKey("kv", "k1")
	if err != nil || !ok || string(mat) != "material" || kver2 != kver {
		t.Fatalf("key: %q %q %v %v", mat, kver2, ok, err)
	}
	_, _, ok, err = st.GetKey("kv", "missing")
	if err != nil || ok {
		t.Fatal("missing key")
	}

	if err := st.PutKeyVaultCertificate("kv", "c1", "", []byte("pem"), ""); err != nil {
		t.Fatal(err)
	}
	cver, pem, policy, ok, err := st.GetKeyVaultCertificate("kv", "c1")
	if err != nil || !ok || string(pem) != "pem" || policy != "{}" || cver == "" {
		t.Fatalf("cert: %q %q %q %v %v", cver, pem, policy, ok, err)
	}
	_, _, _, ok, err = st.GetKeyVaultCertificate("kv", "missing")
	if err != nil || ok {
		t.Fatal("missing cert")
	}
}

func TestStorageAccountRefuseAndGetBlob(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	_, _ = st.UpsertStorageAccount("sub", "rg", "devstoreaccount1", "eastus", "0.0.0.0:4599")
	key, err := st.UpsertStorageAccount("sub", "rg", "a2", "", "127.0.0.1:4599")
	if err != nil || key == "" {
		t.Fatal(err)
	}
	key2, err := st.UpsertStorageAccount("sub", "rg", "a2", "westus", "127.0.0.1:4599")
	if err != nil || key2 != key {
		t.Fatalf("reuse key: %v", err)
	}
	loc, ok, err := st.GetStorageAccount("sub", "rg", "a2")
	if err != nil || !ok || loc != "westus" {
		t.Fatalf("get sa: %q %v %v", loc, ok, err)
	}
	_, ok, err = st.GetStorageAccount("sub", "rg", "missing")
	if err != nil || ok {
		t.Fatal("missing sa")
	}
	_, ok, err = st.GetStorageAccountKey("missing")
	if err != nil || ok {
		t.Fatal("missing key")
	}
	if err := st.CreateContainer("a2", "c"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutBlob("a2", "c", "b", []byte("x"), ""); err != nil {
		t.Fatal(err)
	}
	content, ct, ok, err := st.GetBlob("a2", "c", "b")
	if err != nil || !ok || string(content) != "x" || ct != "application/octet-stream" {
		t.Fatalf("get blob: %q %q %v %v", content, ct, ok, err)
	}
	_, _, ok, err = st.GetBlob("a2", "c", "missing")
	if err != nil || ok {
		t.Fatal("missing blob")
	}
	ok, err = st.DeleteBlob("a2", "c", "missing")
	if err != nil || ok {
		t.Fatal("delete missing")
	}
	_, ok, err = st.Peek("a2", "qmissing")
	if err != nil || ok {
		t.Fatal("peek empty")
	}
	_, ok, err = st.Dequeue("a2", "qmissing", 0)
	if err != nil || ok {
		t.Fatal("dequeue empty")
	}
	_ = config.AzuriteWellKnownCredentials
}

func TestServiceBusTopicsSessionsAndEventHubs(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	sas, err := st.UpsertServiceBusNamespace("sub", "rg", "ns", "")
	if err != nil || sas == "" {
		t.Fatal(err)
	}
	sas2, err := st.UpsertServiceBusNamespace("sub", "rg", "ns", "westus")
	if err != nil || sas2 != sas {
		t.Fatal(err)
	}
	loc, ok, err := st.GetServiceBusNamespace("sub", "rg", "ns")
	if err != nil || !ok || loc != "westus" {
		t.Fatalf("ns: %q %v %v", loc, ok, err)
	}
	_, ok, err = st.GetServiceBusNamespace("sub", "rg", "missing")
	if err != nil || ok {
		t.Fatal("missing ns")
	}
	_, ok, err = st.GetSBNamespaceKey("missing")
	if err != nil || ok {
		t.Fatal("missing sas")
	}
	if err := st.CreateServiceBusQueue("ns", "q"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSBWithMeta("ns", "q", []byte("a"), "sess1", false); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSBWithMeta("ns", "q", []byte("dl"), "", true); err != nil {
		t.Fatal(err)
	}
	body, ok, err := st.DequeueSBWithMeta("ns", "q", "sess1", false)
	if err != nil || !ok || string(body) != "a" {
		t.Fatalf("session: %q %v %v", body, ok, err)
	}
	body, ok, err = st.DequeueSBWithMeta("ns", "q", "", true)
	if err != nil || !ok || string(body) != "dl" {
		t.Fatalf("dl: %q %v %v", body, ok, err)
	}
	_, ok, err = st.DequeueSBWithMeta("ns", "q", "", false)
	if err != nil || ok {
		t.Fatal("empty meta")
	}
	_, ok, err = st.DequeueSB("ns", "q")
	if err != nil || ok {
		t.Fatal("empty sb")
	}

	if err := st.CreateServiceBusTopic("ns", "t1"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServiceBusSubscription("ns", "t1", "sub1", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateServiceBusSubscription("ns", "t1", "sub2", "x"); err != nil {
		t.Fatal(err)
	}
	subs, err := st.ListServiceBusSubscriptions("ns", "t1")
	if err != nil || len(subs) != 2 {
		t.Fatalf("subs: %v %v", subs, err)
	}
	if err := st.EnqueueSBTopic("ns", "t1", "", []byte("fan")); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSBTopic("ns", "t1", "sub1", []byte("direct")); err != nil {
		t.Fatal(err)
	}
	b1, ok, err := st.DequeueSBTopic("ns", "t1", "sub1")
	if err != nil || !ok {
		t.Fatal(err)
	}
	_ = b1
	b2, ok, err := st.DequeueSBTopic("ns", "t1", "sub2")
	if err != nil || !ok || string(b2) != "fan" {
		t.Fatalf("sub2: %q %v %v", b2, ok, err)
	}
	_, ok, err = st.DequeueSBTopic("ns", "t1", "sub2")
	if err != nil || ok {
		t.Fatal("empty topic")
	}

	if err := st.UpsertEventHubsNamespace("sub", "rg", "ehns", ""); err != nil {
		t.Fatal(err)
	}
	loc, ok, err = st.GetEventHubsNamespace("sub", "rg", "ehns")
	if err != nil || !ok || loc != "eastus" {
		t.Fatalf("ehns: %q %v %v", loc, ok, err)
	}
	_, ok, err = st.GetEventHubsNamespace("sub", "rg", "missing")
	if err != nil || ok {
		t.Fatal("missing ehns")
	}
	if err := st.CreateEventHub("ehns", "hub", 0); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateEventHubConsumerGroup("ehns", "hub", "$Default"); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueEventHub("ehns", "hub", "", []byte("e1")); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueEventHub("ehns", "hub", "1", []byte("e2")); err != nil {
		t.Fatal(err)
	}
	body, ok, err = st.DequeueEventHub("ehns", "hub", "0")
	if err != nil || !ok || string(body) != "e1" {
		t.Fatalf("eh0: %q %v %v", body, ok, err)
	}
	body, ok, err = st.DequeueEventHub("ehns", "hub", "")
	if err != nil || !ok || string(body) != "e2" {
		t.Fatalf("eh any: %q %v %v", body, ok, err)
	}
	_, ok, err = st.DequeueEventHub("ehns", "hub", "")
	if err != nil || ok {
		t.Fatal("eh empty")
	}
}

func TestARMRoleAssignmentsAndProviderResources(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	if err := st.EnsureRoot("t", "sub", "root"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertResourceGroup("sub", "rg", "eastus"); err != nil {
		t.Fatal(err)
	}
	loc, ok, err := st.GetResourceGroup("sub", "rg")
	if err != nil || !ok || loc != "eastus" {
		t.Fatalf("rg: %q %v %v", loc, ok, err)
	}
	_, ok, err = st.GetResourceGroup("sub", "missing")
	if err != nil || ok {
		t.Fatal("missing rg")
	}
	rgs, err := st.ListResourceGroups("sub")
	if err != nil || len(rgs) != 1 || rgs[0].Name != "rg" {
		t.Fatalf("list rg: %v %v", rgs, err)
	}

	a := authz.Assignment{ID: "ra1", Scope: "/subscriptions/sub/resourceGroups/rg", RoleDefinitionID: authz.RoleOwner, PrincipalID: "p1"}
	if err := st.UpsertRoleAssignment(a); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.GetRoleAssignment("ra1")
	if err != nil || !ok || got.PrincipalID != "p1" || got.PrincipalType != "ServicePrincipal" {
		t.Fatalf("get ra: %#v %v %v", got, ok, err)
	}
	_, ok, err = st.GetRoleAssignment("missing")
	if err != nil || ok {
		t.Fatal("missing ra")
	}
	list, err := st.ListRoleAssignmentsForScope("/subscriptions/sub/resourceGroups/rg")
	if err != nil || len(list) == 0 {
		t.Fatal(err)
	}
	list2, err := st.ListRoleAssignmentsByScopePrefix("/subscriptions/sub")
	if err != nil || len(list2) == 0 {
		t.Fatal(err)
	}
	if err := store.RequireDB(); err != nil {
		t.Fatal(err)
	}

	if err := st.UpsertProviderResource("Microsoft.Compute/virtualMachines", "sub", "rg", "vm1", "", ""); err != nil {
		t.Fatal(err)
	}
	subRows, err := st.ListProviderResourcesInSubscription("Microsoft.Compute/virtualMachines", "sub")
	if err != nil || len(subRows) != 1 || subRows[0].Name != "vm1" {
		t.Fatalf("list by full type: %v %v", subRows, err)
	}
	nsRows, err := st.ListProviderResourcesInSubscription("Microsoft.Compute", "sub")
	if err != nil || len(nsRows) != 1 || nsRows[0].Name != "vm1" {
		t.Fatalf("list by namespace prefix: %v %v", nsRows, err)
	}
	row, ok, err := st.GetProviderResource("Microsoft.Compute/virtualMachines", "sub", "rg", "vm1")
	if err != nil || !ok || row.Location != "eastus" || row.PropertiesJSON != "{}" {
		t.Fatalf("get prov: %#v %v %v", row, ok, err)
	}
	_, ok, err = st.GetProviderResource("Microsoft.Compute/virtualMachines", "sub", "rg", "missing")
	if err != nil || ok {
		t.Fatal("missing prov")
	}
	rows, err := st.ListProviderResources("Microsoft.Compute/virtualMachines", "sub", "rg")
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %v %v", rows, err)
	}
	byName, ok, err := st.GetProviderResourceByName("Microsoft.Compute/virtualMachines", "vm1")
	if err != nil || !ok || byName.Name != "vm1" {
		t.Fatal(err)
	}
	_, ok, err = st.GetProviderResourceByName("Microsoft.Compute/virtualMachines", "missing")
	if err != nil || ok {
		t.Fatal("missing by name")
	}
	if err := st.DeleteProviderResource("Microsoft.Compute/virtualMachines", "sub", "rg", "vm1"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteProviderResource("Microsoft.Compute/virtualMachines", "sub", "rg", "vm1"); err != sql.ErrNoRows {
		t.Fatalf("want ErrNoRows got %v", err)
	}
}

func TestIdentityEntraCosmosEventGridObserve(t *testing.T) {
	st := openStore(t)
	defer st.Close()

	kid, priv, err := st.EnsureEntraSigningKey()
	if err != nil || kid == "" || priv == nil {
		t.Fatal(err)
	}
	kid2, priv2, err := st.EnsureEntraSigningKey()
	if err != nil || kid2 != kid || priv2 == nil {
		t.Fatal(err)
	}

	if err := st.UpsertManagedIdentity("sub", "rg", "mi", "", "prin", "client"); err != nil {
		t.Fatal(err)
	}
	loc, prin, client, ok, err := st.GetManagedIdentity("sub", "rg", "mi")
	if err != nil || !ok || loc != "eastus" || prin != "prin" || client != "client" {
		t.Fatalf("mi: %v %v", ok, err)
	}
	_, _, _, ok, err = st.GetManagedIdentity("sub", "rg", "missing")
	if err != nil || ok {
		t.Fatal("missing mi")
	}
	mis, err := st.ListManagedIdentities("sub", "rg")
	if err != nil || len(mis) != 1 {
		t.Fatal(err)
	}
	p, n, ok, err := st.FindManagedIdentityByClientID("client")
	if err != nil || !ok || p != "prin" || n != "mi" {
		t.Fatal(err)
	}
	c, n, ok, err := st.FindManagedIdentityByPrincipalID("prin")
	if err != nil || !ok || c != "client" || n != "mi" {
		t.Fatal(err)
	}
	_, _, ok, err = st.FindManagedIdentityByClientID("x")
	if err != nil || ok {
		t.Fatal("missing client")
	}
	ok, err = st.DeleteManagedIdentity("sub", "rg", "mi")
	if err != nil || !ok {
		t.Fatal(err)
	}
	ok, err = st.DeleteManagedIdentity("sub", "rg", "mi")
	if err != nil || ok {
		t.Fatal("second delete")
	}

	if err := st.UpsertSystemAssignedIdentity("sub", "rg", "sai", "", "sp", "sc"); err != nil {
		t.Fatal(err)
	}
	loc, prin, client, ok, err = st.GetSystemAssignedIdentity("sub", "rg", "sai")
	if err != nil || !ok || prin != "sp" {
		t.Fatal(err)
	}
	_, _, _, ok, err = st.GetSystemAssignedIdentity("sub", "rg", "missing")
	if err != nil || ok {
		t.Fatal("missing sai")
	}
	sais, err := st.ListSystemAssignedIdentities("sub", "rg")
	if err != nil || len(sais) != 1 {
		t.Fatal(err)
	}
	ncount, err := st.CountSystemAssignedIdentities()
	if err != nil || ncount != 1 {
		t.Fatal(err)
	}
	fp, fc, ok, err := st.FirstSystemAssignedIdentity()
	if err != nil || !ok || fp != "sp" || fc != "sc" {
		t.Fatal(err)
	}
	ok, err = st.DeleteSystemAssignedIdentity("sub", "rg", "sai")
	if err != nil || !ok {
		t.Fatal(err)
	}
	_, _, ok, err = st.FirstSystemAssignedIdentity()
	if err != nil || ok {
		t.Fatal("first empty")
	}

	appID, err := st.UpsertEntraApp("tenant", "", "App")
	if err != nil || appID == "" {
		t.Fatal(err)
	}
	app, ok, err := st.GetEntraApp("tenant", appID)
	if err != nil || !ok || app.DisplayName != "App" {
		t.Fatal(err)
	}
	apps, err := st.ListEntraApps("tenant")
	if err != nil || len(apps) != 1 {
		t.Fatal(err)
	}
	if err := st.DeleteEntraApp("tenant", appID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteEntraApp("tenant", appID); err != sql.ErrNoRows {
		t.Fatalf("want ErrNoRows got %v", err)
	}

	key, err := st.UpsertCosmosAccount("sub", "rg", "cdb", "")
	if err != nil || key == "" {
		t.Fatal(err)
	}
	key2, err := st.UpsertCosmosAccount("sub", "rg", "cdb", "westus")
	if err != nil || key2 != key {
		t.Fatal(err)
	}
	loc, key3, ok, err := st.GetCosmosAccount("sub", "rg", "cdb")
	if err != nil || !ok || loc != "westus" || key3 != key {
		t.Fatal(err)
	}
	_, _, ok, err = st.GetCosmosAccount("sub", "rg", "missing")
	if err != nil || ok {
		t.Fatal("missing cosmos")
	}
	sub, rg, loc, key4, ok, err := st.GetCosmosAccountByName("cdb")
	if err != nil || !ok || sub != "sub" || rg != "rg" || key4 != key {
		t.Fatal(err)
	}
	if err := st.CreateCosmosDatabase("cdb", "db1"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCosmosContainer("cdb", "db1", "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertCosmosItem("cdb", "db1", "c1", "i1", "pk", `{"id":"i1"}`); err != nil {
		t.Fatal(err)
	}
	body, ok, err := st.GetCosmosItem("cdb", "db1", "c1", "i1", "pk")
	if err != nil || !ok || !strings.Contains(body, "i1") {
		t.Fatal(err)
	}
	_, ok, err = st.GetCosmosItem("cdb", "db1", "c1", "missing", "pk")
	if err != nil || ok {
		t.Fatal("missing item")
	}
	docs, err := st.QueryCosmosItemsByID("cdb", "db1", "c1", "i1")
	if err != nil || len(docs) != 1 {
		t.Fatal(err)
	}

	if err := st.UpsertEventGridTopic("sub", "rg", "egt", ""); err != nil {
		t.Fatal(err)
	}
	_, _, loc, ok, err = st.GetEventGridTopicByName("egt")
	if err != nil || !ok || loc != "eastus" {
		t.Fatal(err)
	}
	_, _, _, ok, err = st.GetEventGridTopicByName("missing")
	if err != nil || ok {
		t.Fatal("missing topic")
	}
	if err := st.UpsertEventGridSubscription("egt", "es1", "http://127.0.0.1:4599/hook", ""); err != nil {
		t.Fatal(err)
	}
	egsubs, err := st.ListEventGridSubscriptions("egt")
	if err != nil || len(egsubs) != 1 {
		t.Fatal(err)
	}
	if err := st.InsertEventGridEvent("egt", `{}`, true); err != nil {
		t.Fatal(err)
	}

	if err := st.UpsertAppConfig("sub", "rg", "ac", ""); err != nil {
		t.Fatal(err)
	}
	ac, ok, err := st.GetAppConfig("sub", "rg", "ac")
	if err != nil || !ok || ac.Name != "ac" {
		t.Fatal(err)
	}
	ac, ok, err = st.GetAppConfigByName("ac")
	if err != nil || !ok {
		t.Fatal(err)
	}
	_, ok, err = st.GetAppConfigByName("missing")
	if err != nil || ok {
		t.Fatal("missing ac")
	}
	acs, err := st.ListAppConfigs("sub", "rg")
	if err != nil || len(acs) != 1 {
		t.Fatal(err)
	}
	if err := st.SetAppConfigKV("", "k", "", "v"); err == nil {
		t.Fatal("expected kv error")
	}
	if err := st.SetAppConfigKV("ac", "k", "", "v"); err != nil {
		t.Fatal(err)
	}
	kv, ok, err := st.GetAppConfigKV("ac", "k", "")
	if err != nil || !ok || kv.Value != "v" {
		t.Fatal(err)
	}
	kvs, err := st.ListAppConfigKV("ac", "")
	if err != nil || len(kvs) != 1 {
		t.Fatal(err)
	}
	if err := st.SetAppConfigFeatureFlag("ac", "ff", true, ""); err != nil {
		t.Fatal(err)
	}
	en, cond, ok, err := st.GetAppConfigFeatureFlag("ac", "ff")
	if err != nil || !ok || !en || cond != "{}" {
		t.Fatal(err)
	}
	ffs, err := st.ListAppConfigFeatureFlags("ac")
	if err != nil || len(ffs) != 1 {
		t.Fatal(err)
	}
	if err := st.UpsertAppConfigSnapshot("ac", "snap", ""); err != nil {
		t.Fatal(err)
	}
	stt, _, ok, err := st.GetAppConfigSnapshot("ac", "snap")
	if err != nil || !ok || stt != "ready" {
		t.Fatal(err)
	}
	_, _, ok, err = st.GetAppConfigSnapshot("ac", "missing")
	if err != nil || ok {
		t.Fatal("missing snap")
	}
	if err := st.DeleteAppConfig("sub", "rg", "ac"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAppConfig("sub", "rg", "ac"); err != sql.ErrNoRows {
		t.Fatalf("want ErrNoRows got %v", err)
	}

	if err := st.UpsertFunctionApp("sub", "rg", "fa", "", ""); err != nil {
		t.Fatal(err)
	}
	fa, ok, err := st.GetFunctionApp("sub", "rg", "fa")
	if err != nil || !ok || fa.MockResponse != "ok" {
		t.Fatal(err)
	}
	fa, ok, err = st.GetFunctionAppByName("fa")
	if err != nil || !ok {
		t.Fatal(err)
	}
	fas, err := st.ListFunctionApps("sub", "rg")
	if err != nil || len(fas) != 1 {
		t.Fatal(err)
	}
	mock, ok, err := st.InvokeFunctionAppMock("fa")
	if err != nil || !ok || mock != "ok" {
		t.Fatal(err)
	}
	_, ok, err = st.InvokeFunctionAppMock("missing")
	if err != nil || ok {
		t.Fatal("missing fa")
	}
	if err := st.DeleteFunctionApp("sub", "rg", "fa"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteFunctionApp("sub", "rg", "fa"); err != sql.ErrNoRows {
		t.Fatalf("want ErrNoRows got %v", err)
	}

	if err := st.AppendActivityLog("c", "op", "/r", "Succeeded", "m"); err != nil {
		t.Fatal(err)
	}
	logs, err := st.ListActivityLog(0)
	if err != nil || len(logs) == 0 {
		t.Fatal(err)
	}
	if err := st.WriteMetric("m1", 1.5, "/r"); err != nil {
		t.Fatal(err)
	}
	metrics, err := st.ListMetrics("", 0)
	if err != nil || len(metrics) == 0 {
		t.Fatal(err)
	}
	if err := st.IngestLogAnalyticsRow("ws", "T", `{"Col":"x"}`); err != nil {
		t.Fatal(err)
	}
	if err := st.IngestLogAnalyticsRow("ws", "T", `{"Col":"y"}`); err != nil {
		t.Fatal(err)
	}
	if err := st.IngestLogAnalyticsRow("ws", "T", "not-json"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.QueryLogAnalyticsKQL("ws", "T | take 1")
	if err != nil || len(rows) != 1 {
		t.Fatalf("take: %v %v", rows, err)
	}
	rows, err = st.QueryLogAnalyticsKQL("ws", `T | where Col == 'x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("where: %v %v", rows, err)
	}
	if err := st.IngestLogAnalyticsRow("ws", "T", `{"TimeGenerated":"2020-06-01T00:00:00Z","Col":"keep","Other":"x"}`); err != nil {
		t.Fatal(err)
	}
	rows, err = st.QueryLogAnalyticsKQL("ws", `T | where TimeGenerated >= datetime('2020-01-01T00:00:00Z') | project Col`)
	if err != nil || len(rows) < 1 {
		t.Fatalf("time/project: %v %v", rows, err)
	}
	if err := st.CaptureEmail("acs", "a@b.c", "hi", "body"); err != nil {
		t.Fatal(err)
	}
}
