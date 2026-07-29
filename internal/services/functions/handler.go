package functions

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

// Handler serves ARM Function App CRUD lite and mock invoke.
type Handler struct {
	Store *store.Store
	Authz *authz.Evaluator
}

type principalFunc func(*http.Request) (authn.Principal, bool)

// Mount registers Function App routes.
func (h *Handler) Mount(mux *http.ServeMux, principalFrom principalFunc) {
	base := "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites"
	mux.HandleFunc("PUT "+base+"/{name}", h.wrap(principalFrom, h.putApp))
	mux.HandleFunc("GET "+base+"/{name}", h.wrap(principalFrom, h.getApp))
	mux.HandleFunc("DELETE "+base+"/{name}", h.wrap(principalFrom, h.deleteApp))
	mux.HandleFunc("GET "+base, h.wrap(principalFrom, h.listApps))
	mux.HandleFunc("POST /functions/{name}/invoke", h.wrap(principalFrom, h.invoke))
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

func siteResourceID(sub, rg, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s", sub, rg, name)
}

func siteResource(row store.FunctionApp) map[string]any {
	return map[string]any{
		"id":       siteResourceID(row.SubscriptionID, row.ResourceGroup, row.Name),
		"name":     row.Name,
		"type":     "Microsoft.Web/sites",
		"kind":     "functionapp",
		"location": row.Location,
		"properties": map[string]any{
			"state":             "Running",
			"provisioningState": "Succeeded",
			"defaultHostName":   fmt.Sprintf("%s.azurewebsites.lab", row.Name),
			"labMockResponse":   row.MockResponse,
		},
	}
}

func (h *Handler) putApp(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	scope := siteResourceID(sub, rg, name)
	if err := h.require(p, "Microsoft.Web/sites/write", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	var body struct {
		Location   string `json:"location"`
		Kind       string `json:"kind"`
		Properties struct {
			LabMockResponse string `json:"labMockResponse"`
		} `json:"properties"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Location == "" {
		body.Location = "eastus"
	}
	mock := body.Properties.LabMockResponse
	if mock == "" {
		mock = `{"ok":true}`
	}
	if err := h.Store.UpsertFunctionApp(sub, rg, name, body.Location, mock); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_ = h.Store.AppendActivityLog(p.ID, "Microsoft.Web/sites/write", scope, "Succeeded", "")
	row, _, _ := h.Store.GetFunctionApp(sub, rg, name)
	writeJSON(w, http.StatusOK, siteResource(row))
}

func (h *Handler) getApp(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	scope := siteResourceID(sub, rg, name)
	if err := h.require(p, "Microsoft.Web/sites/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	row, ok, err := h.Store.GetFunctionApp(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "function app not found")
		return
	}
	writeJSON(w, http.StatusOK, siteResource(row))
}

func (h *Handler) deleteApp(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	scope := siteResourceID(sub, rg, name)
	if err := h.require(p, "Microsoft.Web/sites/delete", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	if err := h.Store.DeleteFunctionApp(sub, rg, name); err != nil {
		if err == sql.ErrNoRows {
			azerrors.NotFound(w, "function app not found")
			return
		}
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_ = h.Store.AppendActivityLog(p.ID, "Microsoft.Web/sites/delete", scope, "Succeeded", "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listApps(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg := r.PathValue("sub"), r.PathValue("rg")
	scope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", sub, rg)
	if err := h.require(p, "Microsoft.Web/sites/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	rows, err := h.Store.ListFunctionApps(sub, rg)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]any, 0, len(rows))
	for _, row := range rows {
		value = append(value, siteResource(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (h *Handler) invoke(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	name := r.PathValue("name")
	row, ok, err := h.Store.GetFunctionAppByName(name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "function app not found")
		return
	}
	scope := siteResourceID(row.SubscriptionID, row.ResourceGroup, row.Name)
	if err := h.require(p, "Microsoft.Web/sites/functions/write", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)
	mock, _, err := h.Store.InvokeFunctionAppMock(name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if strings.TrimSpace(mock) == "" {
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}
	if json.Valid([]byte(mock)) {
		_, _ = w.Write([]byte(mock))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"result": mock})
}
