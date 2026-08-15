package entra

import (
	"encoding/json"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func (s *Service) requirePrincipal(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := authn.PrincipalFromContext(r.Context()); !ok {
		azerrors.Unauthenticated(w, "")
		return false
	}
	return true
}

func (s *Service) appTenant() string {
	if s.TenantID != "" {
		return s.TenantID
	}
	return "00000000-0000-0000-0000-000000000001"
}

func (s *Service) handleListApps(w http.ResponseWriter, r *http.Request) {
	if !s.requirePrincipal(w, r) {
		return
	}
	apps, err := s.Store.ListEntraApps(s.appTenant())
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]any, 0, len(apps))
	for _, a := range apps {
		value = append(value, map[string]any{
			"id": a.AppID, "appId": a.AppID, "displayName": a.DisplayName, "createdDateTime": a.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	if !s.requirePrincipal(w, r) {
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
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": appID, "appId": appID, "displayName": body.DisplayName})
}

func (s *Service) handleGetApp(w http.ResponseWriter, r *http.Request) {
	if !s.requirePrincipal(w, r) {
		return
	}
	row, ok, err := s.Store.GetEntraApp(s.appTenant(), r.PathValue("appId"))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "application not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": row.AppID, "appId": row.AppID, "displayName": row.DisplayName, "createdDateTime": row.CreatedAt,
	})
}

func (s *Service) handlePatchApp(w http.ResponseWriter, r *http.Request) {
	if !s.requirePrincipal(w, r) {
		return
	}
	var body struct {
		DisplayName string `json:"displayName"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	tenant, appID := s.appTenant(), r.PathValue("appId")
	if _, ok, err := s.Store.GetEntraApp(tenant, appID); err != nil || !ok {
		azerrors.NotFound(w, "application not found")
		return
	}
	if _, err := s.Store.UpsertEntraApp(tenant, appID, body.DisplayName); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	row, _, _ := s.Store.GetEntraApp(tenant, appID)
	writeJSON(w, http.StatusOK, map[string]any{"id": row.AppID, "appId": row.AppID, "displayName": row.DisplayName})
}

func (s *Service) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	if !s.requirePrincipal(w, r) {
		return
	}
	if err := s.Store.DeleteEntraApp(s.appTenant(), r.PathValue("appId")); err != nil {
		azerrors.NotFound(w, "application not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
