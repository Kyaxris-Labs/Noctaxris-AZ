package hostroute_test

import (
	"net/http"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/hostroute"
)

func TestRewritePathAzureHosts(t *testing.T) {
	cases := []struct {
		host, path, want string
	}{
		{"127.0.0.1:4599", "/blob/a/c", "/blob/a/c"},
		{"localhost", "/keyvault/v/secrets/s", "/keyvault/v/secrets/s"},
		{"myvault.vault.azure.net", "/secrets/s1", "/keyvault/myvault/secrets/s1"},
		{"myvault.vault.azure.net", "/keyvault/other/secrets/s1", "/keyvault/myvault/secrets/s1"},
		{"acct.blob.core.windows.net", "/artifacts", "/blob/acct/artifacts"},
		{"acct.blob.core.windows.net", "/blob/other/artifacts", "/blob/acct/artifacts"},
		{"acct.blob.core.windows.net", "/artifacts/tfstate", "/blob/acct/artifacts/tfstate"},
		{"acct.queue.core.windows.net", "/q1", "/queue/acct/q1"},
		{"acct.table.core.windows.net", "/t1", "/table/acct/t1"},
		{"store.azconfig.io", "/kv/routes.night", "/appconfig/store/kv/routes.night"},
		{"store.azconfig.io", "/appconfig/evil/kv/x", "/appconfig/store/kv/x"},
		{"graph.microsoft.com", "/v1.0/applications", "/v1.0/applications"},
		{"acct.blob.core.windows.net", "/foo/../artifacts", "/blob/acct/artifacts"},
	}
	for _, tc := range cases {
		if got := hostroute.RewritePath(tc.host, tc.path); got != tc.want {
			t.Fatalf("RewritePath(%q,%q)=%q want %q", tc.host, tc.path, got, tc.want)
		}
	}
}

func TestApplyMutatesRequest(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "https://v1.vault.azure.net/secrets/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "v1.vault.azure.net"
	hostroute.Apply(r)
	if r.URL.Path != "/keyvault/v1/secrets/x" {
		t.Fatalf("path=%q", r.URL.Path)
	}
}

func TestRejectEmptyHostLabel(t *testing.T) {
	if got := hostroute.RewritePath(".vault.azure.net", "/secrets/x"); got != "/secrets/x" {
		t.Fatalf("got %q", got)
	}
}
