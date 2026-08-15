package server

import "testing"

func TestCanonicalizeARMPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"/subscriptions/s/resourcegroups/rg", "/subscriptions/s/resourceGroups/rg"},
		{"/subscriptions/s/resourcegroups/rg/providers/Microsoft.Storage/storageAccounts/stci",
			"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stci"},
		{"/subscriptions/s/resourceGroups/rg", "/subscriptions/s/resourceGroups/rg"},
		{"/subscriptions/s/RESOURCEGROUPS/rg", "/subscriptions/s/resourceGroups/rg"},
		{"/keyvault/kv-ci/secrets/demo", "/keyvault/kv-ci/secrets/demo"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := canonicalizeARMPath(tc.in); got != tc.want {
			t.Fatalf("canonicalizeARMPath(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}
