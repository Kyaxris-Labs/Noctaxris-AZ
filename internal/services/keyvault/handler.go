package keyvault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
	"golang.org/x/crypto/chacha20poly1305"
)

// Handler serves Key Vault ARM and data-plane routes.
type Handler struct {
	Store           *store.Store
	Auth            *authn.Authenticator
	Authz           *authz.Evaluator
	AuthorizationURL string
	Resource        string
}

// Register mounts Key Vault routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}", h.putVault)
	mux.HandleFunc("GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}", h.getVault)

	mux.HandleFunc("PUT /keyvault/{vault}/secrets/{name}", h.putSecret)
	mux.HandleFunc("GET /keyvault/{vault}/secrets/{name}", h.getSecret)

	mux.HandleFunc("PUT /keyvault/{vault}/keys/{name}", h.putKey)
	mux.HandleFunc("GET /keyvault/{vault}/keys/{name}", h.getKey)
	mux.HandleFunc("POST /keyvault/{vault}/keys/{name}/encrypt", h.encrypt)
	mux.HandleFunc("POST /keyvault/{vault}/keys/{name}/decrypt", h.decrypt)
}

func (h *Handler) putVault(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.KeyVault/vaults/write", armScope(r)) {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	name := r.PathValue("name")
	location := "eastus"
	var body struct {
		Location string `json:"location"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if body.Location != "" {
		location = body.Location
	}
	if err := h.Store.UpsertKeyVault(sub, rg, name, location); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.KeyVault/vaults/" + name
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"name":     name,
		"type":     "Microsoft.KeyVault/vaults",
		"location": location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
			"vaultUri":          "/keyvault/" + name,
		},
	})
}

func (h *Handler) getVault(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.KeyVault/vaults/read", armScope(r)) {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	name := r.PathValue("name")
	location, ok, err := h.Store.GetKeyVault(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "vault not found")
		return
	}
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.KeyVault/vaults/" + name
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"name":     name,
		"type":     "Microsoft.KeyVault/vaults",
		"location": location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
			"vaultUri":          "/keyvault/" + name,
		},
	})
}

func (h *Handler) putSecret(w http.ResponseWriter, r *http.Request) {
	if !h.requireDataPlaneBearer(w, r) {
		return
	}
	vault := r.PathValue("vault")
	name := r.PathValue("name")
	if ok, err := h.Store.KeyVaultExists(vault); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	} else if !ok {
		azerrors.NotFound(w, "vault not found")
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.Value == "" {
		azerrors.BadRequest(w, "value is required")
		return
	}
	version, err := h.Store.PutSecret(vault, name, body.Value)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, secretResponse(vault, name, version, body.Value))
}

func (h *Handler) getSecret(w http.ResponseWriter, r *http.Request) {
	if !h.requireDataPlaneBearer(w, r) {
		return
	}
	vault := r.PathValue("vault")
	name := r.PathValue("name")
	value, version, ok, err := h.Store.GetSecret(vault, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "secret not found")
		return
	}
	writeJSON(w, http.StatusOK, secretResponse(vault, name, version, value))
}

func (h *Handler) putKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireDataPlaneBearer(w, r) {
		return
	}
	vault := r.PathValue("vault")
	name := r.PathValue("name")
	if ok, err := h.Store.KeyVaultExists(vault); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	} else if !ok {
		azerrors.NotFound(w, "vault not found")
		return
	}
	material := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	version, err := h.Store.PutKey(vault, name, material)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key": map[string]any{
			"kid": "/keyvault/" + vault + "/keys/" + name + "/" + version,
			"kty": "oct",
		},
		"attributes": map[string]any{"enabled": true, "created": time.Now().UTC().Unix()},
	})
}

func (h *Handler) getKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireDataPlaneBearer(w, r) {
		return
	}
	vault := r.PathValue("vault")
	name := r.PathValue("name")
	_, version, ok, err := h.Store.GetKey(vault, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "key not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key": map[string]any{
			"kid": "/keyvault/" + vault + "/keys/" + name + "/" + version,
			"kty": "oct",
		},
		"attributes": map[string]any{"enabled": true},
	})
}

func (h *Handler) encrypt(w http.ResponseWriter, r *http.Request) {
	if !h.requireDataPlaneBearer(w, r) {
		return
	}
	vault := r.PathValue("vault")
	name := r.PathValue("name")
	key, _, ok, err := h.Store.GetKey(vault, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "key not found")
		return
	}
	var body struct {
		Value string `json:"value"`
		Alg   string `json:"alg"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.Value == "" {
		azerrors.BadRequest(w, "value is required")
		return
	}
	plain, err := base64.StdEncoding.DecodeString(body.Value)
	if err != nil {
		plain = []byte(body.Value)
	}
	aead, err := chacha20poly1305.New(normalizeKey(key))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	ct := aead.Seal(nonce, nonce, plain, nil)
	writeJSON(w, http.StatusOK, map[string]string{
		"kid":   "/keyvault/" + vault + "/keys/" + name,
		"value": base64.StdEncoding.EncodeToString(ct),
	})
}

func (h *Handler) decrypt(w http.ResponseWriter, r *http.Request) {
	if !h.requireDataPlaneBearer(w, r) {
		return
	}
	vault := r.PathValue("vault")
	name := r.PathValue("name")
	key, _, ok, err := h.Store.GetKey(vault, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "key not found")
		return
	}
	var body struct {
		Value string `json:"value"`
		Alg   string `json:"alg"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.Value == "" {
		azerrors.BadRequest(w, "value is required")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.Value)
	if err != nil {
		azerrors.BadRequest(w, "value must be base64")
		return
	}
	aead, err := chacha20poly1305.New(normalizeKey(key))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if len(raw) < aead.NonceSize() {
		azerrors.BadRequest(w, "ciphertext too short")
		return
	}
	nonce, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		azerrors.BadRequest(w, "decrypt failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"kid":   "/keyvault/" + vault + "/keys/" + name,
		"value": base64.StdEncoding.EncodeToString(plain),
	})
}

func normalizeKey(key []byte) []byte {
	out := make([]byte, 32)
	copy(out, key)
	return out
}

func secretResponse(vault, name, version, value string) map[string]any {
	return map[string]any{
		"value": value,
		"id":    "/keyvault/" + vault + "/secrets/" + name + "/" + version,
		"attributes": map[string]any{
			"enabled": true,
			"created": time.Now().UTC().Unix(),
			"updated": time.Now().UTC().Unix(),
		},
	}
}

func (h *Handler) requireDataPlaneBearer(w http.ResponseWriter, r *http.Request) bool {
	authzURL := h.AuthorizationURL
	if authzURL == "" {
		authzURL = "http://127.0.0.1:4599"
	}
	resource := h.Resource
	if resource == "" {
		resource = "https://vault.azure.net"
	}
	raw := r.Header.Get("Authorization")
	if !strings.HasPrefix(raw, "Bearer ") {
		azerrors.KeyVaultUnauthenticated(w, authzURL, resource)
		return false
	}
	if h.Auth == nil {
		azerrors.KeyVaultUnauthenticated(w, authzURL, resource)
		return false
	}
	if _, err := h.Auth.AuthenticateRequest(r); err != nil {
		azerrors.KeyVaultUnauthenticated(w, authzURL, resource)
		return false
	}
	_ = r.URL.Query().Get("api-version")
	return true
}

func (h *Handler) requireBearerARM(w http.ResponseWriter, r *http.Request, action, scope string) bool {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	p, err := h.Auth.AuthenticateRequest(r)
	if err != nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	if h.Authz == nil {
		if p.IsRoot {
			return true
		}
		azerrors.Forbidden(w, "")
		return false
	}
	ok, err := h.Authz.Evaluate(p.ID, p.IsRoot, action, scope)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return false
	}
	if !ok {
		azerrors.Forbidden(w, "")
		return false
	}
	return true
}

func armScope(r *http.Request) string {
	return "/subscriptions/" + r.PathValue("sub") + "/resourceGroups/" + r.PathValue("rg")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
