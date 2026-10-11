package store_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func TestHashUserPasswordBcryptAndLegacyMatch(t *testing.T) {
	hash := store.HashUserPassword("LabUser!Pass1")
	if hash == "" || !strings.HasPrefix(hash, "$2") {
		t.Fatalf("expected bcrypt hash, got %q", hash)
	}
	if !store.MatchPasswordHash(hash, "LabUser!Pass1") {
		t.Fatal("bcrypt match failed")
	}
	if store.MatchPasswordHash(hash, "wrong") {
		t.Fatal("bcrypt wrong password matched")
	}
	if store.HashUserPassword("LabUser!Pass1") == hash {
		t.Fatal("expected distinct bcrypt salts")
	}
	sum := sha256.Sum256([]byte("legacy-pass"))
	legacy := hex.EncodeToString(sum[:])
	if !store.MatchPasswordHash(legacy, "legacy-pass") {
		t.Fatal("legacy sha256 match failed")
	}
	if store.MatchPasswordHash(legacy, "other") {
		t.Fatal("legacy wrong password matched")
	}
	if store.MatchPasswordHash("", "x") || store.MatchPasswordHash(hash, "") {
		t.Fatal("empty sides must not match")
	}
}
