package appconfig

import (
	"encoding/json"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func (h *Handler) putFeatureFlag(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	storeName, name := r.PathValue("store"), r.PathValue("name")
	st, ok, err := h.Store.GetAppConfigByName(storeName)
	if err != nil || !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	scope := storeResourceID(st.SubscriptionID, st.ResourceGroup, st.Name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/keyValues/write", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	var body struct {
		Enabled    bool           `json:"enabled"`
		Conditions map[string]any `json:"conditions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	cond := "{}"
	if body.Conditions != nil {
		b, _ := json.Marshal(body.Conditions)
		cond = string(b)
	}
	if err := h.Store.SetAppConfigFeatureFlag(storeName, name, body.Enabled, cond); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": name, "enabled": body.Enabled, "conditions": body.Conditions})
}

func (h *Handler) getFeatureFlag(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	storeName, name := r.PathValue("store"), r.PathValue("name")
	st, ok, err := h.Store.GetAppConfigByName(storeName)
	if err != nil || !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	scope := storeResourceID(st.SubscriptionID, st.ResourceGroup, st.Name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/keyValues/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	enabled, cond, ok, err := h.Store.GetAppConfigFeatureFlag(storeName, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "feature flag not found")
		return
	}
	var conditions any
	_ = json.Unmarshal([]byte(cond), &conditions)
	writeJSON(w, http.StatusOK, map[string]any{"id": name, "enabled": enabled, "conditions": conditions})
}

func (h *Handler) listFeatureFlags(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	storeName := r.PathValue("store")
	st, ok, err := h.Store.GetAppConfigByName(storeName)
	if err != nil || !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	scope := storeResourceID(st.SubscriptionID, st.ResourceGroup, st.Name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/keyValues/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	rows, err := h.Store.ListAppConfigFeatureFlags(storeName)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]any, 0, len(rows))
	for _, row := range rows {
		var conditions any
		_ = json.Unmarshal([]byte(row.ConditionsJSON), &conditions)
		items = append(items, map[string]any{"id": row.Name, "enabled": row.Enabled, "conditions": conditions})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) putSnapshot(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	storeName, name := r.PathValue("store"), r.PathValue("name")
	st, ok, err := h.Store.GetAppConfigByName(storeName)
	if err != nil || !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	scope := storeResourceID(st.SubscriptionID, st.ResourceGroup, st.Name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/keyValues/write", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	if err := h.Store.UpsertAppConfigSnapshot(storeName, name, "ready"); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "status": "ready"})
}

func (h *Handler) getSnapshot(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	storeName, name := r.PathValue("store"), r.PathValue("name")
	st, ok, err := h.Store.GetAppConfigByName(storeName)
	if err != nil || !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	scope := storeResourceID(st.SubscriptionID, st.ResourceGroup, st.Name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/keyValues/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	status, created, ok, err := h.Store.GetAppConfigSnapshot(storeName, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "snapshot not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "status": status, "createdAt": created})
}
