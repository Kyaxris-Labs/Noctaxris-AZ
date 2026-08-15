package azerrors_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

func TestWriteHelpers(t *testing.T) {
	cases := []struct {
		name string
		fn   func(http.ResponseWriter)
		code int
		arm  string
	}{
		{"unauth default", func(w http.ResponseWriter) { azerrors.Unauthenticated(w, "") }, 401, "AuthenticationFailed"},
		{"unauth msg", func(w http.ResponseWriter) { azerrors.Unauthenticated(w, "nope") }, 401, "AuthenticationFailed"},
		{"forbidden default", func(w http.ResponseWriter) { azerrors.Forbidden(w, "") }, 403, "AuthorizationFailed"},
		{"forbidden msg", func(w http.ResponseWriter) { azerrors.Forbidden(w, "no") }, 403, "AuthorizationFailed"},
		{"notfound", func(w http.ResponseWriter) { azerrors.NotFound(w, "gone") }, 404, "ResourceNotFound"},
		{"bad", func(w http.ResponseWriter) { azerrors.BadRequest(w, "bad") }, 400, "BadRequest"},
		{"conflict", func(w http.ResponseWriter) { azerrors.Conflict(w, "c") }, 409, "Conflict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.fn(rec)
			if rec.Code != tc.code {
				t.Fatalf("status %d", rec.Code)
			}
			var env azerrors.ARMError
			if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
				t.Fatal(err)
			}
			if env.Error.Code != tc.arm {
				t.Fatalf("code %q", env.Error.Code)
			}
		})
	}

	rec := httptest.NewRecorder()
	azerrors.KeyVaultUnauthenticated(rec, "", "")
	if rec.Code != 401 {
		t.Fatal(rec.Code)
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if wa == "" {
		t.Fatal("missing WWW-Authenticate")
	}
	rec2 := httptest.NewRecorder()
	azerrors.KeyVaultUnauthenticated(rec2, "http://auth", "https://vault.azure.net")
	if rec2.Code != 401 {
		t.Fatal(rec2.Code)
	}

	rec3 := httptest.NewRecorder()
	azerrors.StorageError(rec3, 403, "AuthorizationFailure", "denied")
	if rec3.Code != 403 || rec3.Header().Get("x-ms-error-code") != "AuthorizationFailure" {
		t.Fatalf("%d %v", rec3.Code, rec3.Header())
	}
	azerrors.WriteARM(httptest.NewRecorder(), 500, "InternalError", "x")
}
