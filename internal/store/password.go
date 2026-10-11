package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = bcrypt.DefaultCost

func opaqueHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// HashUserPassword returns a bcrypt hash for directory user passwords and app client secrets.
func HashUserPassword(password string) string {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		// Fail closed to a non-matching sentinel rather than panicking seed paths.
		return ""
	}
	return string(b)
}

// MatchPasswordHash reports whether password matches a stored bcrypt or legacy SHA-256 hex digest.
func MatchPasswordHash(stored, password string) bool {
	if stored == "" || password == "" {
		return false
	}
	switch {
	case strings.HasPrefix(stored, "$2a$"), strings.HasPrefix(stored, "$2b$"), strings.HasPrefix(stored, "$2y$"):
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	default:
		// Legacy unsalted SHA-256 hex (pre-1.4.3 user passwords and HashToken client secrets).
		return stored == opaqueHash(password)
	}
}
