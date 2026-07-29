package authorization

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

// Service serves Microsoft.Authorization role assignment ARM APIs.
type Service struct {
	Store          *store.Store
	Authz          *authz.Evaluator
	PrincipalFrom  func(context.Context) (authn.Principal, bool)
	SubscriptionID string
}

// Mount registers role assignment routes.
func (s *Service) Mount(mux *http.ServeMux) {
	mux.HandleFunc("PUT /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments/{roleAssignmentName}", s.putAtSubscription)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments/{roleAssignmentName}", s.getAtSubscription)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments", s.listAtSubscription)
	mux.HandleFunc("PUT /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/roleAssignments/{roleAssignmentName}", s.putAtResourceGroup)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/roleAssignments/{roleAssignmentName}", s.getAtResourceGroup)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/roleAssignments", s.listAtResourceGroup)
}

func (s *Service) principal(ctx context.Context) (authn.Principal, bool) {
	if s.PrincipalFrom != nil {
		return s.PrincipalFrom(ctx)
	}
	return authn.PrincipalFromContext(ctx)
}

func requireAPIVersion(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.URL.Query().Get("api-version")) == "" {
		azerrors.BadRequest(w, "api-version query parameter is required")
		return false
	}
	return true
}

func (s *Service) require(w http.ResponseWriter, r *http.Request, action, scope string) (authn.Principal, bool) {
	p, ok := s.principal(r.Context())
	if !ok {
		azerrors.Unauthenticated(w, "")
		return authn.Principal{}, false
	}
	allowed, err := s.Authz.Evaluate(p.ID, p.IsRoot, action, scope)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return authn.Principal{}, false
	}
	if !allowed {
		azerrors.Forbidden(w, "")
		return authn.Principal{}, false
	}
	return p, true
}

func (s *Service) putAtSubscription(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("subscriptionId")
	name := r.PathValue("roleAssignmentName")
	scope := "/subscriptions/" + subID
	id := scope + "/providers/Microsoft.Authorization/roleAssignments/" + name
	s.putRoleAssignment(w, r, scope, id, name)
}

func (s *Service) getAtSubscription(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("subscriptionId")
	name := r.PathValue("roleAssignmentName")
	scope := "/subscriptions/" + subID
	id := scope + "/providers/Microsoft.Authorization/roleAssignments/" + name
	s.getRoleAssignment(w, r, scope, id, name)
}

func (s *Service) putAtResourceGroup(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("subscriptionId")
	rg := r.PathValue("resourceGroupName")
	name := r.PathValue("roleAssignmentName")
	scope := "/subscriptions/" + subID + "/resourceGroups/" + rg
	id := scope + "/providers/Microsoft.Authorization/roleAssignments/" + name
	s.putRoleAssignment(w, r, scope, id, name)
}

func (s *Service) getAtResourceGroup(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("subscriptionId")
	rg := r.PathValue("resourceGroupName")
	name := r.PathValue("roleAssignmentName")
	scope := "/subscriptions/" + subID + "/resourceGroups/" + rg
	id := scope + "/providers/Microsoft.Authorization/roleAssignments/" + name
	s.getRoleAssignment(w, r, scope, id, name)
}

func (s *Service) listAtSubscription(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("subscriptionId")
	scope := "/subscriptions/" + subID
	s.listRoleAssignments(w, r, scope)
}

func (s *Service) listAtResourceGroup(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("subscriptionId")
	rg := r.PathValue("resourceGroupName")
	scope := "/subscriptions/" + subID + "/resourceGroups/" + rg
	s.listRoleAssignments(w, r, scope)
}

func (s *Service) listRoleAssignments(w http.ResponseWriter, r *http.Request, scope string) {
	if !requireAPIVersion(w, r) {
		return
	}
	if _, ok := s.require(w, r, "Microsoft.Authorization/roleAssignments/read", scope); !ok {
		return
	}
	list, err := s.Store.ListRoleAssignmentsByScopePrefix(scope)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(list))
	for _, a := range list {
		name := a.ID
		if i := strings.LastIndex(a.ID, "/"); i >= 0 {
			name = a.ID[i+1:]
		}
		value = append(value, roleAssignmentJSON(a, name))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) putRoleAssignment(w http.ResponseWriter, r *http.Request, scope, id, name string) {
	if !requireAPIVersion(w, r) {
		return
	}
	p, ok := s.require(w, r, "Microsoft.Authorization/roleAssignments/write", scope)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, "unable to read body")
		return
	}
	var req struct {
		Properties struct {
			RoleDefinitionID string `json:"roleDefinitionId"`
			PrincipalID      string `json:"principalId"`
			PrincipalType    string `json:"principalType"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		azerrors.BadRequest(w, "invalid JSON body")
		return
	}
	roleDef := strings.TrimSpace(req.Properties.RoleDefinitionID)
	principalID := strings.TrimSpace(req.Properties.PrincipalID)
	if roleDef == "" || principalID == "" {
		azerrors.BadRequest(w, "properties.roleDefinitionId and properties.principalId are required")
		return
	}
	principalType := strings.TrimSpace(req.Properties.PrincipalType)
	if principalType == "" {
		principalType = "ServicePrincipal"
	}
	a := authz.Assignment{
		ID:               id,
		Scope:            scope,
		RoleDefinitionID: roleDef,
		PrincipalID:      principalID,
		PrincipalType:    principalType,
	}
	if err := s.Store.UpsertRoleAssignment(a); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_ = s.Store.AppendActivityLog(p.ID, "Microsoft.Authorization/roleAssignments/write", id, "Succeeded", "")
	writeJSON(w, http.StatusOK, roleAssignmentJSON(a, name))
}

func (s *Service) getRoleAssignment(w http.ResponseWriter, r *http.Request, scope, id, name string) {
	if !requireAPIVersion(w, r) {
		return
	}
	if _, ok := s.require(w, r, "Microsoft.Authorization/roleAssignments/read", scope); !ok {
		return
	}
	a, ok, err := s.Store.GetRoleAssignment(id)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "Role assignment not found")
		return
	}
	writeJSON(w, http.StatusOK, roleAssignmentJSON(a, name))
}

func roleAssignmentJSON(a authz.Assignment, name string) map[string]any {
	pt := a.PrincipalType
	if pt == "" {
		pt = "ServicePrincipal"
	}
	return map[string]any{
		"id":   a.ID,
		"name": name,
		"type": "Microsoft.Authorization/roleAssignments",
		"properties": map[string]any{
			"roleDefinitionId": a.RoleDefinitionID,
			"principalId":      a.PrincipalID,
			"principalType":    pt,
			"scope":            a.Scope,
		},
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
