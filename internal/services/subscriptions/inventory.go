package subscriptions

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func (s *Service) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	if _, ok := s.require(w, r, "Microsoft.Resources/subscriptions/read", "/subscriptions"); !ok {
		return
	}
	list, err := s.Store.ListSubscriptions()
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(list))
	for _, row := range list {
		id := row["id"]
		value = append(value, map[string]any{
			"id":             "/subscriptions/" + id,
			"subscriptionId": id,
			"displayName":    row["displayName"],
			"state":          row["state"],
			"tenantId":       row["tenantId"],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) listTenants(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	if _, ok := s.require(w, r, "Microsoft.Resources/tenants/read", "/tenants"); !ok {
		return
	}
	tid := ""
	subs, _ := s.Store.ListSubscriptions()
	if len(subs) > 0 {
		tid = subs[0]["tenantId"]
	}
	if tid == "" {
		tid = s.SubscriptionID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"value": []map[string]any{{
			"id":             "/tenants/" + tid,
			"tenantId":       tid,
			"displayName":    "Noctaxris-AZ Lab",
			"tenantCategory": "Home",
		}},
	})
}

func (s *Service) listManagementGroups(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	if _, ok := s.require(w, r, "Microsoft.Management/managementGroups/read", "/providers/Microsoft.Management/managementGroups"); !ok {
		return
	}
	list, err := s.Store.ListManagementGroups()
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(list))
	for _, row := range list {
		id := row["id"]
		value = append(value, map[string]any{
			"id":   "/providers/Microsoft.Management/managementGroups/" + id,
			"name": id,
			"type": "Microsoft.Management/managementGroups",
			"properties": map[string]any{
				"displayName": row["displayName"],
				"tenantId":    row["tenantId"],
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) listManagementGroupDescendants(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	groupID := strings.TrimSpace(r.PathValue("id"))
	if groupID == "" {
		azerrors.BadRequest(w, "management group id is required")
		return
	}
	scope := "/providers/Microsoft.Management/managementGroups/" + groupID
	if _, ok := s.require(w, r, "Microsoft.Management/managementGroups/read", scope); !ok {
		return
	}
	_, tenantID, parentID, ok, err := s.Store.GetManagementGroup(groupID)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok || (strings.TrimSpace(s.TenantID) != "" && tenantID != s.TenantID) {
		azerrors.NotFound(w, "Management group not found")
		return
	}
	value := make([]map[string]any, 0)
	children, err := s.Store.ListChildManagementGroups(groupID, tenantID)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	for _, row := range children {
		id := row["id"]
		value = append(value, map[string]any{
			"id":   "/providers/Microsoft.Management/managementGroups/" + id,
			"name": id,
			"type": "Microsoft.Management/managementGroups",
		})
	}
	if parentID == "" {
		subs, err := s.Store.ListSubscriptionsForTenant(tenantID)
		if err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		for _, row := range subs {
			id := row["id"]
			value = append(value, map[string]any{
				"id":   "/subscriptions/" + id,
				"name": id,
				"type": "Microsoft.Management/managementGroups/subscriptions",
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) listEmptyARM(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	if _, ok := s.require(w, r, "Microsoft.Resources/resources/read", "/subscriptions/"+subID); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": []any{}})
}

func (s *Service) listSubProvider(armType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAPIVersion(w, r) {
			return
		}
		subID := r.PathValue("subscriptionId")
		if _, ok := s.require(w, r, "Microsoft.Resources/resources/read", "/subscriptions/"+subID); !ok {
			return
		}
		rows, err := s.Store.ListProviderResourcesInSubscription(armType, subID)
		if err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		value := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			value = append(value, armResourceJSON(row, armType))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": value})
	}
}

func armResourceJSON(row store.ProviderResource, armType string) map[string]any {
	return map[string]any{
		"id":       "/subscriptions/" + row.SubscriptionID + "/resourceGroups/" + row.ResourceGroup + "/providers/" + armType + "/" + row.Name,
		"name":     row.Name,
		"type":     armType,
		"location": row.Location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
		},
	}
}

func (s *Service) listStorageAccounts(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	if _, ok := s.require(w, r, "Microsoft.Storage/storageAccounts/read", "/subscriptions/"+subID); !ok {
		return
	}
	rows, err := s.Store.ListStorageAccountsInSubscription(subID)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := map[string]any{
			"id":       "/subscriptions/" + row.SubscriptionID + "/resourceGroups/" + row.ResourceGroup + "/providers/Microsoft.Storage/storageAccounts/" + row.Name,
			"name":     row.Name,
			"type":     "Microsoft.Storage/storageAccounts",
			"location": row.Location,
		}
		containers, _ := s.Store.ListContainers(row.Name)
		if len(containers) > 0 {
			item["properties"] = map[string]any{"containerCount": len(containers)}
		}
		value = append(value, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) listWebSites(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	if _, ok := s.require(w, r, "Microsoft.Web/sites/read", "/subscriptions/"+subID); !ok {
		return
	}
	web, err := s.Store.ListProviderResourcesInSubscription("Microsoft.Web/sites", subID)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0)
	for _, row := range web {
		item := armResourceJSON(row, "Microsoft.Web/sites")
		item["kind"] = "app"
		value = append(value, item)
	}
	apps, err := s.Store.ListFunctionAppsInSubscription(subID)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	for _, app := range apps {
		value = append(value, map[string]any{
			"id":       "/subscriptions/" + app.SubscriptionID + "/resourceGroups/" + app.ResourceGroup + "/providers/Microsoft.Web/sites/" + app.Name,
			"name":     app.Name,
			"type":     "Microsoft.Web/sites",
			"kind":     "functionapp",
			"location": app.Location,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) queryResourceGraph(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	if _, ok := s.require(w, r, "Microsoft.ResourceGraph/resources/read", "/providers/Microsoft.ResourceGraph/resources"); !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, "unable to read body")
		return
	}
	var req struct {
		Query         string   `json:"query"`
		Subscriptions []string `json:"subscriptions"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			azerrors.BadRequest(w, "invalid JSON body")
			return
		}
	}
	table, typeFilter, limit := parseARGQuery(req.Query)
	rows, err := s.Store.ListARGResources(table, typeFilter)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totalRecords":    len(rows),
		"count":           len(rows),
		"data":            rows,
		"resultTruncated": "false",
	})
}

func parseARGQuery(q string) (table, typeFilter string, limit int) {
	q = strings.TrimSpace(q)
	lower := strings.ToLower(q)
	switch {
	case strings.Contains(lower, "securityresources"):
		table = "SecurityResources"
	case strings.Contains(lower, "resources"):
		table = "Resources"
	}
	if i := strings.Index(lower, "type =="); i >= 0 {
		rest := q[i+len("type =="):]
		rest = strings.TrimSpace(rest)
		rest = strings.Trim(rest, `"'`)
		if j := strings.IndexAny(rest, " |"); j >= 0 {
			rest = rest[:j]
		}
		typeFilter = strings.Trim(rest, `"'`)
	}
	if i := strings.Index(lower, "limit "); i >= 0 {
		fmtN := strings.TrimSpace(q[i+6:])
		n, _ := strconv.Atoi(strings.Fields(fmtN + " 0")[0])
		limit = n
	}
	return table, typeFilter, limit
}
