package authorization

import (
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
)

func (s *Service) mountRoleDefinitions(mux *http.ServeMux) {
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions", s.listRoleDefinitionsAtSubscription)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/{roleDefinitionId}", s.getRoleDefinitionAtSubscription)
	mux.HandleFunc("GET /providers/Microsoft.Authorization/roleDefinitions", s.listRoleDefinitionsTenant)
	mux.HandleFunc("GET /providers/Microsoft.Authorization/roleDefinitions/{roleDefinitionId}", s.getRoleDefinitionTenant)
}

func (s *Service) listRoleDefinitionsAtSubscription(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	sub := r.PathValue("subscriptionId")
	if _, ok := s.require(w, r, "Microsoft.Authorization/roleDefinitions/read", "/subscriptions/"+sub); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": roleDefinitionList("/subscriptions/" + sub)})
}

func (s *Service) getRoleDefinitionAtSubscription(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	sub := r.PathValue("subscriptionId")
	id := strings.TrimSpace(r.PathValue("roleDefinitionId"))
	if _, ok := s.require(w, r, "Microsoft.Authorization/roleDefinitions/read", "/subscriptions/"+sub); !ok {
		return
	}
	doc, ok := roleDefinitionByName("/subscriptions/"+sub, id)
	if !ok {
		azerrors.WriteARM(w, http.StatusNotFound, "ResourceNotFound", "role definition not found")
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Service) listRoleDefinitionsTenant(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	if _, ok := s.require(w, r, "Microsoft.Authorization/roleDefinitions/read", "/"); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": roleDefinitionList("")})
}

func (s *Service) getRoleDefinitionTenant(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("roleDefinitionId"))
	if _, ok := s.require(w, r, "Microsoft.Authorization/roleDefinitions/read", "/"); !ok {
		return
	}
	doc, ok := roleDefinitionByName("", id)
	if !ok {
		azerrors.WriteARM(w, http.StatusNotFound, "ResourceNotFound", "role definition not found")
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func roleDefinitionList(scopePrefix string) []map[string]any {
	roles := authz.BuiltInRoles()
	out := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		out = append(out, authz.RoleDefinitionARM(scopePrefix, role))
	}
	return out
}

func roleDefinitionByName(scopePrefix, name string) (map[string]any, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, role := range authz.BuiltInRoles() {
		if strings.EqualFold(role.Name, name) {
			return authz.RoleDefinitionARM(scopePrefix, role), true
		}
	}
	return nil, false
}
