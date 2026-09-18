package monitor

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func (h *Handler) mountDiagnosticSettings(mux *http.ServeMux, principalFrom principalFunc) {
	subBase := "/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings"
	mux.HandleFunc("PUT "+subBase+"/{name}", h.wrap(principalFrom, h.putDiagnosticSetting))
	mux.HandleFunc("GET "+subBase+"/{name}", h.wrap(principalFrom, h.getDiagnosticSetting))
	mux.HandleFunc("DELETE "+subBase+"/{name}", h.wrap(principalFrom, h.deleteDiagnosticSetting))
	mux.HandleFunc("GET "+subBase, h.wrap(principalFrom, h.listDiagnosticSettings))

	resBase := "/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{rtype}/{res}/providers/Microsoft.Insights/diagnosticSettings"
	mux.HandleFunc("PUT "+resBase+"/{name}", h.wrap(principalFrom, h.putDiagnosticSetting))
	mux.HandleFunc("GET "+resBase+"/{name}", h.wrap(principalFrom, h.getDiagnosticSetting))
	mux.HandleFunc("DELETE "+resBase+"/{name}", h.wrap(principalFrom, h.deleteDiagnosticSetting))
	mux.HandleFunc("GET "+resBase, h.wrap(principalFrom, h.listDiagnosticSettings))
}

func diagnosticTargetID(r *http.Request) string {
	sub := r.PathValue("sub")
	res := r.PathValue("res")
	if res == "" {
		return "/subscriptions/" + sub
	}
	return "/subscriptions/" + sub + "/resourceGroups/" + r.PathValue("rg") +
		"/providers/" + r.PathValue("provider") + "/" + r.PathValue("rtype") + "/" + res
}

func diagnosticSettingID(target, name string) string {
	return strings.TrimRight(target, "/") + "/providers/Microsoft.Insights/diagnosticSettings/" + name
}

func (h *Handler) putDiagnosticSetting(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	target := diagnosticTargetID(r)
	name := r.PathValue("name")
	if err := h.require(p, "Microsoft.Insights/diagnosticSettings/write", target); err != nil {
		writeAuthz(w, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	var body struct {
		Properties map[string]any `json:"properties"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			azerrors.BadRequest(w, "invalid JSON body")
			return
		}
	}
	if body.Properties == nil {
		body.Properties = map[string]any{}
	}
	workspaceID, _ := body.Properties["workspaceId"].(string)
	id := diagnosticSettingID(target, name)
	props, _ := json.Marshal(body.Properties)
	if err := h.Store.UpsertDiagnosticSetting(id, target, name, workspaceID, string(props)); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_ = h.Store.AppendActivityLogRow(store.ActivityLogRow{
		Timestamp:  h.now(),
		Caller:     p.ID,
		Operation:  "Microsoft.Insights/diagnosticSettings/write",
		ResourceID: id,
		Status:     "Succeeded",
		ClientIP:   requestClientIP(r),
	})
	writeJSON(w, http.StatusOK, diagnosticSettingJSON(id, name, body.Properties))
}

func (h *Handler) getDiagnosticSetting(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	target := diagnosticTargetID(r)
	name := r.PathValue("name")
	if err := h.require(p, "Microsoft.Insights/diagnosticSettings/read", target); err != nil {
		writeAuthz(w, err)
		return
	}
	id := diagnosticSettingID(target, name)
	row, ok, err := h.Store.GetDiagnosticSetting(id)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "diagnostic setting not found")
		return
	}
	writeJSON(w, http.StatusOK, diagnosticSettingFromRow(row))
}

func (h *Handler) deleteDiagnosticSetting(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	target := diagnosticTargetID(r)
	name := r.PathValue("name")
	if err := h.require(p, "Microsoft.Insights/diagnosticSettings/delete", target); err != nil {
		writeAuthz(w, err)
		return
	}
	id := diagnosticSettingID(target, name)
	if err := h.Store.DeleteDiagnosticSetting(id); err != nil {
		if err == sql.ErrNoRows {
			azerrors.NotFound(w, "diagnostic setting not found")
			return
		}
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_ = h.Store.AppendActivityLogRow(store.ActivityLogRow{
		Timestamp:  h.now(),
		Caller:     p.ID,
		Operation:  "Microsoft.Insights/diagnosticSettings/delete",
		ResourceID: id,
		Status:     "Succeeded",
		ClientIP:   requestClientIP(r),
	})
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) listDiagnosticSettings(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	target := diagnosticTargetID(r)
	if err := h.require(p, "Microsoft.Insights/diagnosticSettings/read", target); err != nil {
		writeAuthz(w, err)
		return
	}
	rows, err := h.Store.ListDiagnosticSettings(target)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]any, 0, len(rows))
	for _, row := range rows {
		value = append(value, diagnosticSettingFromRow(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func diagnosticSettingFromRow(row map[string]string) map[string]any {
	var props map[string]any
	if json.Unmarshal([]byte(row["properties"]), &props) != nil {
		props = map[string]any{}
	}
	return diagnosticSettingJSON(row["id"], row["name"], props)
}

func diagnosticSettingJSON(id, name string, props map[string]any) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	return map[string]any{
		"id":         id,
		"name":       name,
		"type":       "Microsoft.Insights/diagnosticSettings",
		"properties": props,
	}
}
