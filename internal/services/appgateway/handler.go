package appgateway

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const providerKey = "Microsoft.Network/applicationGateways"
const armType = "Microsoft.Network/applicationGateways"

// Handler serves Microsoft.Network/applicationGateways ARM lite.
type Handler struct {
	Store *store.Store
	Auth  *authn.Authenticator
	Authz *authz.Evaluator
}

// Register mounts routes.
func (h *Handler) Register(mux *http.ServeMux) {
	base := "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/applicationGateways"
	mux.HandleFunc("PUT "+base+"/{name}", h.put)
	mux.HandleFunc("GET "+base+"/{name}", h.get)
	mux.HandleFunc("DELETE "+base+"/{name}", h.del)
	mux.HandleFunc("GET "+base, h.list)
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.Network/applicationGateways/write") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	location := "eastus"
	props := map[string]any{"provisioningState": "Succeeded"}
	var body struct {
		Location   string         `json:"location"`
		Properties map[string]any `json:"properties"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if body.Location != "" {
		location = body.Location
	}
	if body.Properties != nil {
		for k, v := range body.Properties {
			props[k] = v
		}
	}
	b, _ := json.Marshal(props)
	if err := h.Store.UpsertProviderResource(providerKey, sub, rg, name, location, string(b)); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resourceJSON(sub, rg, name, location, props))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.Network/applicationGateways/read") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	row, ok, err := h.Store.GetProviderResource(providerKey, sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "resource not found")
		return
	}
	var props map[string]any
	_ = json.Unmarshal([]byte(row.PropertiesJSON), &props)
	if props == nil {
		props = map[string]any{"provisioningState": "Succeeded"}
	}
	writeJSON(w, http.StatusOK, resourceJSON(sub, rg, name, row.Location, props))
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.Network/applicationGateways/delete") {
		return
	}
	err := h.Store.DeleteProviderResource(providerKey, r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name"))
	if err == sql.ErrNoRows {
		azerrors.NotFound(w, "resource not found")
		return
	}
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.Network/applicationGateways/read") {
		return
	}
	rows, err := h.Store.ListProviderResources(providerKey, r.PathValue("sub"), r.PathValue("rg"))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	value := make([]any, 0, len(rows))
	for _, row := range rows {
		var props map[string]any
		_ = json.Unmarshal([]byte(row.PropertiesJSON), &props)
		value = append(value, resourceJSON(row.SubscriptionID, row.ResourceGroup, row.Name, row.Location, props))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func resourceJSON(sub, rg, name, location string, props map[string]any) map[string]any {
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.Network/applicationGateways/" + name
	return map[string]any{
		"id": id, "name": name, "type": armType, "location": location, "properties": props,
	}
}

func (h *Handler) require(w http.ResponseWriter, r *http.Request, action string) bool {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	p, err := h.Auth.AuthenticateRequest(r)
	if err != nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	if !p.AllowsARM() {
		azerrors.InvalidAuthenticationTokenAudience(w, "")
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
