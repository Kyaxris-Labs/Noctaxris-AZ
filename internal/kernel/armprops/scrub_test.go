package armprops_test

import (
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/armprops"
)

func TestPublicOmitsSecretKeys(t *testing.T) {
	got := armprops.Public(map[string]any{
		"provisioningState":          "Succeeded",
		"administratorLogin":         "sqladmin",
		"administratorLoginPassword": "SuperSecret!",
		"primaryKey":                 "pk",
		"connectionString":           "Server=...;Password=x",
		"accessKeyEnabled":           true,
		"version":                    "12.0",
	})
	if got["administratorLoginPassword"] != nil || got["primaryKey"] != nil || got["connectionString"] != nil {
		t.Fatalf("secrets leaked: %#v", got)
	}
	if got["administratorLogin"] != "sqladmin" || got["provisioningState"] != "Succeeded" {
		t.Fatalf("non-secrets missing: %#v", got)
	}
	if got["accessKeyEnabled"] != true {
		t.Fatalf("accessKeyEnabled should remain: %#v", got)
	}
	if armprops.Public(nil) == nil {
		t.Fatal("nil props should become empty map")
	}
}
