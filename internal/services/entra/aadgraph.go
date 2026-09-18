package entra

import (
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

func (s *Service) requireAADGraph(w http.ResponseWriter, r *http.Request) bool {
	if !s.requireGraph(w, r) {
		return false
	}
	if strings.TrimSpace(r.URL.Query().Get("api-version")) == "" {
		azerrors.WriteGraph(w, http.StatusBadRequest, "BadRequest", "api-version is required")
		return false
	}
	return true
}

func (s *Service) handleAADTenantDetails(w http.ResponseWriter, r *http.Request) {
	if !s.requireAADGraph(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"value": []map[string]any{{
			"objectId":          s.appTenant(),
			"displayName":       "Noctaxris-AZ Lab",
			"verifiedDomains":   []map[string]any{{"name": "lab.local", "default": true}},
			"dirSyncEnabled":    false,
			"companyLastDirSyncTime": nil,
		}},
	})
}

func (s *Service) handleAADUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAADGraph(w, r) {
		return
	}
	users, err := s.Store.ListDirectoryUsers(s.appTenant())
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(users))
	for _, u := range users {
		value = append(value, map[string]any{
			"objectId":            u.ID,
			"displayName":         u.DisplayName,
			"userPrincipalName":   u.UserPrincipalName,
			"mail":                u.Mail,
			"accountEnabled":      true,
			"userType":            "Member",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) handleAADDirectoryRoles(w http.ResponseWriter, r *http.Request) {
	if !s.requireAADGraph(w, r) {
		return
	}
	roles, err := s.Store.ListDirectoryRoles(s.appTenant())
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		members, _ := s.Store.ListDirectoryRoleMembers(role.ID)
		ms := make([]map[string]any, 0, len(members))
		for _, id := range members {
			ms = append(ms, map[string]any{"objectId": id, "url": "directoryObjects/" + id})
		}
		value = append(value, map[string]any{
			"objectId":        role.ID,
			"displayName":     role.DisplayName,
			"roleTemplateId":  role.TemplateID,
			"members":         ms,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}
