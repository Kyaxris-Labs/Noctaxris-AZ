package azerrors

import (
	"encoding/json"
	"net/http"
)

// ARMError is the Azure Resource Manager error envelope.
type ARMError struct {
	Error ARMErrorBody `json:"error"`
}

// ARMErrorBody is the nested ARM error object.
type ARMErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteARM writes an ARM-shaped JSON error.
func WriteARM(w http.ResponseWriter, httpCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(ARMError{Error: ARMErrorBody{Code: code, Message: message}})
}

// Unauthenticated writes HTTP 401.
func Unauthenticated(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Authentication failed. The Authorization header is missing or invalid."
	}
	WriteARM(w, http.StatusUnauthorized, "AuthenticationFailed", message)
}

// KeyVaultUnauthenticated writes 401 with WWW-Authenticate for Key Vault data plane.
func KeyVaultUnauthenticated(w http.ResponseWriter, authorization, resource string) {
	if authorization == "" {
		authorization = "http://127.0.0.1:4599"
	}
	if resource == "" {
		resource = "https://vault.azure.net"
	}
	w.Header().Set("WWW-Authenticate", `Bearer authorization="`+authorization+`", resource="`+resource+`"`)
	WriteARM(w, http.StatusUnauthorized, "Unauthorized", "AKV10000: Request is missing a Bearer or PoP token.")
}

// Forbidden writes HTTP 403.
func Forbidden(w http.ResponseWriter, message string) {
	if message == "" {
		message = "The client does not have permission to perform this operation."
	}
	WriteARM(w, http.StatusForbidden, "AuthorizationFailed", message)
}

// NotFound writes HTTP 404.
func NotFound(w http.ResponseWriter, message string) {
	WriteARM(w, http.StatusNotFound, "ResourceNotFound", message)
}

// BadRequest writes HTTP 400.
func BadRequest(w http.ResponseWriter, message string) {
	WriteARM(w, http.StatusBadRequest, "BadRequest", message)
}

// Conflict writes HTTP 409.
func Conflict(w http.ResponseWriter, message string) {
	WriteARM(w, http.StatusConflict, "Conflict", message)
}

// StorageError writes a Storage-shaped XML/JSON lite error using ARM envelope for lab JSON clients.
func StorageError(w http.ResponseWriter, httpCode int, code, message string) {
	w.Header().Set("x-ms-error-code", code)
	WriteARM(w, httpCode, code, message)
}
