package acr

import "testing"

func TestSanitizeScopeName(t *testing.T) {
	if got := sanitizeScopeName("repo/app_v1-2.3"); got != "repo/app_v1-2.3" {
		t.Fatalf("keep %q", got)
	}
	if got := sanitizeScopeName("repo name!@#/x"); got != "reponame/x" {
		t.Fatalf("strip %q", got)
	}
	if got := sanitizeScopeName(""); got != "" {
		t.Fatalf("empty %q", got)
	}
}
