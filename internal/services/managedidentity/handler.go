package managedidentity

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/services/entra"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
	"github.com/google/uuid"
)

// Handler serves Managed Identity ARM and IMDS token theatre.
type Handler struct {
	Store    *store.Store
	Auth     *authn.Authenticator
	Authz    *authz.Evaluator
	Entra    *entra.Service
	TenantID string
}

// Register mounts Managed Identity routes.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}", h.putIdentity)
	mux.HandleFunc("GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}", h.getIdentity)
	mux.HandleFunc("DELETE /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}", h.deleteIdentity)
	mux.HandleFunc("GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities", h.listIdentities)
	mux.HandleFunc("GET /metadata/identity/oauth2/token", h.imdsToken)
}

func (h *Handler) putIdentity(w http.ResponseWriter, r *http.Request) {
	if !h.requireARM(w, r, "Microsoft.ManagedIdentity/userAssignedIdentities/write") {
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
	principalID := uuid.NewString()
	clientID := uuid.NewString()
	if existingLoc, p, c, ok, err := h.Store.GetManagedIdentity(sub, rg, name); err == nil && ok {
		location = existingLoc
		principalID, clientID = p, c
	} else if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if err := h.Store.UpsertManagedIdentity(sub, rg, name, location, principalID, clientID); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, identityJSON(sub, rg, name, location, principalID, clientID, h.TenantID))
}

func (h *Handler) getIdentity(w http.ResponseWriter, r *http.Request) {
	if !h.requireARM(w, r, "Microsoft.ManagedIdentity/userAssignedIdentities/read") {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	name := r.PathValue("name")
	location, principalID, clientID, ok, err := h.Store.GetManagedIdentity(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "identity not found")
		return
	}
	writeJSON(w, http.StatusOK, identityJSON(sub, rg, name, location, principalID, clientID, h.TenantID))
}

func (h *Handler) deleteIdentity(w http.ResponseWriter, r *http.Request) {
	if !h.requireARM(w, r, "Microsoft.ManagedIdentity/userAssignedIdentities/delete") {
		return
	}
	ok, err := h.Store.DeleteManagedIdentity(r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name"))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "identity not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) listIdentities(w http.ResponseWriter, r *http.Request) {
	if !h.requireARM(w, r, "Microsoft.ManagedIdentity/userAssignedIdentities/read") {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	list, err := h.Store.ListManagedIdentities(sub, rg)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(list))
	for _, row := range list {
		value = append(value, identityJSON(sub, rg, row.Name, row.Location, row.PrincipalID, row.ClientID, h.TenantID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (h *Handler) imdsToken(w http.ResponseWriter, r *http.Request) {
	// Microsoft Learn: Metadata header must be the lowercase string "true"
	// (SSRF mitigation). api-version >= 2018-02-01 and resource are required.
	// https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/how-to-use-vm-token
	if r.Header.Get("Metadata") != "true" {
		writeIMDSError(w, http.StatusBadRequest, "bad_request_102", "Required metadata header not specified")
		return
	}
	apiVersion := strings.TrimSpace(r.URL.Query().Get("api-version"))
	if apiVersion == "" {
		writeIMDSError(w, http.StatusBadRequest, "bad_request", "api-version is required (use 2018-02-01 or later)")
		return
	}
	resource := strings.TrimSpace(r.URL.Query().Get("resource"))
	if resource == "" {
		writeIMDSError(w, http.StatusBadRequest, "bad_request", "resource is required")
		return
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	objectID := strings.TrimSpace(r.URL.Query().Get("object_id"))
	principalID := "managed-identity"
	resolvedClientID := clientID

	switch {
	case clientID != "":
		p, _, ok, err := h.Store.FindManagedIdentityByClientID(clientID)
		if err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		if ok {
			principalID = p
		} else {
			principalID = clientID
		}
	case objectID != "":
		c, _, ok, err := h.Store.FindManagedIdentityByPrincipalID(objectID)
		if err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		if !ok {
			writeIMDSError(w, http.StatusBadRequest, "invalid_request", "Identity not found")
			return
		}
		principalID = objectID
		resolvedClientID = c
	}

	if h.Entra == nil {
		azerrors.WriteARM(w, http.StatusServiceUnavailable, "ServiceUnavailable", "entra signing unavailable")
		return
	}
	aud := strings.TrimRight(resource, "/")
	token, expiresIn, err := h.Entra.MintAccessToken(principalID, aud)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	now := time.Now().UTC()
	expOn := now.Add(time.Duration(expiresIn) * time.Second).Unix()
	// IMDS returns several lifetime fields as JSON strings.
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":   token,
		"client_id":      resolvedClientID,
		"expires_in":     strconv.Itoa(expiresIn),
		"expires_on":     strconv.FormatInt(expOn, 10),
		"ext_expires_in": strconv.Itoa(expiresIn),
		"not_before":     strconv.FormatInt(now.Unix(), 10),
		"resource":       resource,
		"token_type":     "Bearer",
	})
}

func writeIMDSError(w http.ResponseWriter, code int, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

func (h *Handler) requireARM(w http.ResponseWriter, r *http.Request, action string) bool {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	p, err := h.Auth.AuthenticateRequest(r)
	if err != nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	scope := "/subscriptions/" + r.PathValue("sub") + "/resourceGroups/" + r.PathValue("rg")
	if h.Authz == nil {
		return p.IsRoot
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

func identityJSON(sub, rg, name, location, principalID, clientID, tenantID string) map[string]any {
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" + name
	return map[string]any{
		"id":       id,
		"name":     name,
		"type":     "Microsoft.ManagedIdentity/userAssignedIdentities",
		"location": location,
		"properties": map[string]any{
			"principalId":       principalID,
			"clientId":          clientID,
			"tenantId":          tenantID,
			"provisioningState": "Succeeded",
		},
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
