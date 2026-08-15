package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func (h *Handler) putWorkspace(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	scope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", sub, rg)
	if err := h.require(p, "Microsoft.OperationalInsights/workspaces/write", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	props := `{"provisioningState":"Succeeded"}`
	if err := h.Store.UpsertProviderResource("Microsoft.OperationalInsights/workspaces", sub, rg, name, "eastus", props); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.OperationalInsights/workspaces/" + name,
		"name": name, "type": "Microsoft.OperationalInsights/workspaces", "location": "eastus",
		"properties": map[string]any{"provisioningState": "Succeeded"},
	})
}

func (h *Handler) getWorkspace(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	scope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", sub, rg)
	if err := h.require(p, "Microsoft.OperationalInsights/workspaces/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	row, ok, err := h.Store.GetProviderResource("Microsoft.OperationalInsights/workspaces", sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "workspace not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.OperationalInsights/workspaces/" + name,
		"name": name, "type": "Microsoft.OperationalInsights/workspaces", "location": row.Location,
		"properties": map[string]any{"provisioningState": "Succeeded"},
	})
}

func (h *Handler) queryKQL(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	if err := h.require(p, "Microsoft.OperationalInsights/workspaces/query/action", "/"); err != nil {
		writeAuthz(w, err)
		return
	}
	var body struct {
		Query string `json:"query"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	rows, err := h.Store.QueryLogAnalyticsKQL(r.PathValue("workspace"), body.Query)
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tables": []map[string]any{{"name": "PrimaryResult", "rows": rows}}})
}

func (h *Handler) ingestRows(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	if err := h.require(p, "Microsoft.OperationalInsights/workspaces/write", "/"); err != nil {
		writeAuthz(w, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		var one map[string]any
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			azerrors.BadRequest(w, "expected JSON object or array")
			return
		}
		rows = []map[string]any{one}
	}
	for _, row := range rows {
		b, _ := json.Marshal(row)
		if err := h.Store.IngestLogAnalyticsRow(r.PathValue("workspace"), r.PathValue("table"), string(b)); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ingested": len(rows)})
}
