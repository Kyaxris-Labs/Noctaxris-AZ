package authn_test

import (
	"net/http"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func TestTableSASCreateRequiresC(t *testing.T) {
	path := "/table/acct1/people"
	if authn.SASPermits("a", http.MethodPut, path) {
		t.Fatal("sp=a must not create table")
	}
	if authn.SASPermits("w", http.MethodPut, path) {
		t.Fatal("sp=w must not create table")
	}
	if authn.SASPermits("raud", http.MethodPut, path) {
		t.Fatal("sp=raud without c must not create table")
	}
	if !authn.SASPermits("c", http.MethodPut, path) {
		t.Fatal("sp=c must create table")
	}
	if !authn.SASPermits("a", http.MethodPost, path) {
		t.Fatal("sp=a must insert entity")
	}
}
