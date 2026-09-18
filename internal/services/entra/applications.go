package entra

import (
	"encoding/json"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

func (s *Service) requirePrincipal(w http.ResponseWriter, r *http.Request) bool {
	return s.requireGraph(w, r)
}

func (s *Service) appTenant() string {
	if s.TenantID != "" {
		return s.TenantID
	}
	return "00000000-0000-0000-0000-000000000001"
}

func appGraphJSON(objectID, appID, displayName, created string) map[string]any {
	id := objectID
	if id == "" {
		id = appID
	}
	return map[string]any{
		"id": id, "appId": appID, "displayName": displayName, "createdDateTime": created,
	}
}

func (s *Service) handleListApps(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	apps, err := s.Store.ListEntraApps(s.appTenant())
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		value = append(value, appGraphJSON(a.ObjectID, a.AppID, a.DisplayName, a.CreatedAt))
	}
	s.writeOData(w, r, value)
}

func (s *Service) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		DisplayName string `json:"displayName"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.DisplayName == "" {
		body.DisplayName = "lab-app"
	}
	appID, err := s.Store.UpsertEntraApp(s.appTenant(), "", body.DisplayName)
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	row, _, _ := s.Store.GetEntraApp(s.appTenant(), appID)
	writeJSON(w, http.StatusCreated, appGraphJSON(row.ObjectID, row.AppID, row.DisplayName, row.CreatedAt))
}

func (s *Service) handleGetApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	row, ok, err := s.Store.GetEntraApp(s.appTenant(), r.PathValue("appId"))
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "application not found")
		return
	}
	writeJSON(w, http.StatusOK, appGraphJSON(row.ObjectID, row.AppID, row.DisplayName, row.CreatedAt))
}

func (s *Service) handlePatchApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		DisplayName     string           `json:"displayName"`
		KeyCredentials  []map[string]any `json:"keyCredentials"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	tenant, appID := s.appTenant(), r.PathValue("appId")
	row, ok, err := s.Store.GetEntraApp(tenant, appID)
	if err != nil || !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "application not found")
		return
	}
	if body.DisplayName != "" {
		if _, err := s.Store.UpsertEntraApp(tenant, row.AppID, body.DisplayName); err != nil {
			azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	obj := row.ObjectID
	if obj == "" {
		obj = row.AppID
	}
	for _, kc := range body.KeyCredentials {
		keyPEM, _ := kc["key"].(string)
		if keyPEM == "" {
			continue
		}
		if _, err := s.Store.AddKeyCredential(obj, "application", keyPEM, "Verify", "AsymmetricX509Cert"); err != nil {
			azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	row, _, _ = s.Store.GetEntraApp(tenant, row.AppID)
	writeJSON(w, http.StatusOK, appGraphJSON(row.ObjectID, row.AppID, row.DisplayName, row.CreatedAt))
}

func (s *Service) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	if err := s.Store.DeleteEntraApp(s.appTenant(), r.PathValue("appId")); err != nil {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "application not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
