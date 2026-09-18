package entra

import (
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

func (s *Service) mountIAMPortal(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/Users", s.handleIAMUsers)
}

func (s *Service) handleIAMUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	users, err := s.Store.ListDirectoryUsers(s.appTenant())
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(users))
	for _, u := range users {
		items = append(items, map[string]any{
			"objectId": u.ID, "displayName": u.DisplayName, "userPrincipalName": u.UserPrincipalName,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items, "items": items})
}
