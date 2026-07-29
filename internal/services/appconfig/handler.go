package appconfig

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

// Handler serves ARM App Configuration stores and data-plane key-values.
type Handler struct {
	Store *store.Store
	Authz *authz.Evaluator
}

type principalFunc func(*http.Request) (authn.Principal, bool)

// Mount registers App Configuration routes.
func (h *Handler) Mount(mux *http.ServeMux, principalFrom principalFunc) {
	base := "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.AppConfiguration/configurationStores"
	mux.HandleFunc("PUT "+base+"/{name}", h.wrap(principalFrom, h.putStore))
	mux.HandleFunc("GET "+base+"/{name}", h.wrap(principalFrom, h.getStore))
	mux.HandleFunc("DELETE "+base+"/{name}", h.wrap(principalFrom, h.deleteStore))
	mux.HandleFunc("GET "+base, h.wrap(principalFrom, h.listStores))

	mux.HandleFunc("GET /appconfig/{store}/kv/{key}", h.wrap(principalFrom, h.getKV))
	mux.HandleFunc("PUT /appconfig/{store}/kv/{key}", h.wrap(principalFrom, h.putKV))
	mux.HandleFunc("GET /appconfig/{store}/kv", h.wrap(principalFrom, h.listKV))
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p authn.Principal)

func (h *Handler) wrap(principalFrom principalFunc, fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFrom(r)
		if !ok {
			azerrors.Unauthenticated(w, "")
			return
		}
		fn(w, r, p)
	}
}

func (h *Handler) require(p authn.Principal, action, scope string) error {
	ok, err := h.Authz.Evaluate(p.ID, p.IsRoot, action, scope)
	if err != nil {
		return err
	}
	if !ok {
		return errDenied
	}
	return nil
}

var errDenied = fmt.Errorf("permission denied")

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAuthz(w http.ResponseWriter, err error) {
	if err == errDenied {
		azerrors.Forbidden(w, "")
		return
	}
	azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
}

func storeResourceID(sub, rg, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.AppConfiguration/configurationStores/%s",
		sub, rg, name)
}

func storeResource(row store.AppConfigStore) map[string]any {
	return map[string]any{
		"id":       storeResourceID(row.SubscriptionID, row.ResourceGroup, row.Name),
		"name":     row.Name,
		"type":     "Microsoft.AppConfiguration/configurationStores",
		"location": row.Location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
			"endpoint":          fmt.Sprintf("http://127.0.0.1:4599/appconfig/%s", row.Name),
		},
	}
}

func (h *Handler) putStore(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	scope := storeResourceID(sub, rg, name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/write", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	var body struct {
		Location   string         `json:"location"`
		Properties map[string]any `json:"properties"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Location == "" {
		body.Location = "eastus"
	}
	if err := h.Store.UpsertAppConfig(sub, rg, name, body.Location); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_ = h.Store.AppendActivityLog(p.ID, "Microsoft.AppConfiguration/configurationStores/write", scope, "Succeeded", "")
	row, _, _ := h.Store.GetAppConfig(sub, rg, name)
	writeJSON(w, http.StatusOK, storeResource(row))
}

func (h *Handler) getStore(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	scope := storeResourceID(sub, rg, name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	row, ok, err := h.Store.GetAppConfig(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	writeJSON(w, http.StatusOK, storeResource(row))
}

func (h *Handler) deleteStore(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	scope := storeResourceID(sub, rg, name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/delete", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	if err := h.Store.DeleteAppConfig(sub, rg, name); err != nil {
		if err == sql.ErrNoRows {
			azerrors.NotFound(w, "configuration store not found")
			return
		}
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_ = h.Store.AppendActivityLog(p.ID, "Microsoft.AppConfiguration/configurationStores/delete", scope, "Succeeded", "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listStores(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg := r.PathValue("sub"), r.PathValue("rg")
	scope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", sub, rg)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	rows, err := h.Store.ListAppConfigs(sub, rg)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]any, 0, len(rows))
	for _, row := range rows {
		value = append(value, storeResource(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (h *Handler) putKV(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	storeName := r.PathValue("store")
	key, _ := url.PathUnescape(r.PathValue("key"))
	label := r.URL.Query().Get("label")
	st, ok, err := h.Store.GetAppConfigByName(storeName)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	scope := storeResourceID(st.SubscriptionID, st.ResourceGroup, st.Name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/keyValues/write", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	var body struct {
		Value string `json:"value"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		azerrors.BadRequest(w, "invalid JSON body")
		return
	}
	if body.Label != "" {
		label = body.Label
	}
	if err := h.Store.SetAppConfigKV(storeName, key, label, body.Value); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, kvResource(storeName, key, label, body.Value))
}

func (h *Handler) getKV(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	storeName := r.PathValue("store")
	key, _ := url.PathUnescape(r.PathValue("key"))
	label := r.URL.Query().Get("label")
	st, ok, err := h.Store.GetAppConfigByName(storeName)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	scope := storeResourceID(st.SubscriptionID, st.ResourceGroup, st.Name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/keyValues/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	row, ok, err := h.Store.GetAppConfigKV(storeName, key, label)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "key not found")
		return
	}
	writeJSON(w, http.StatusOK, kvResource(row.Store, row.Key, row.Label, row.Value))
}

func (h *Handler) listKV(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	storeName := r.PathValue("store")
	keyFilter := r.URL.Query().Get("key")
	st, ok, err := h.Store.GetAppConfigByName(storeName)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "configuration store not found")
		return
	}
	scope := storeResourceID(st.SubscriptionID, st.ResourceGroup, st.Name)
	if err := h.require(p, "Microsoft.AppConfiguration/configurationStores/keyValues/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	rows, err := h.Store.ListAppConfigKV(storeName, keyFilter)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]any, 0, len(rows))
	for _, row := range rows {
		items = append(items, kvResource(row.Store, row.Key, row.Label, row.Value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func kvResource(storeName, key, label, value string) map[string]any {
	etag := strings.TrimSpace(key) + "|" + label
	return map[string]any{
		"key":          key,
		"label":        label,
		"value":        value,
		"content_type": "",
		"etag":         etag,
		"locked":       false,
	}
}
