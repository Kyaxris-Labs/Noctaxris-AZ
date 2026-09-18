package entra

import (
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func (s *Service) mountGraph(mux *http.ServeMux) {
	for _, p := range []string{"/v1.0", "/beta"} {
		mux.HandleFunc("GET "+p+"/organization", s.handleGraphOrganization)
		mux.HandleFunc("GET "+p+"/users", s.handleGraphUsers)
		mux.HandleFunc("GET "+p+"/users/{id}", s.handleGraphUser)
		mux.HandleFunc("PATCH "+p+"/users/{id}", s.handlePatchUser)
		mux.HandleFunc("GET "+p+"/groups", s.handleGraphGroups)
		mux.HandleFunc("GET "+p+"/groups/{id}", s.handleGraphGroup)
		mux.HandleFunc("GET "+p+"/groups/{id}/members", s.handleGraphGroupMembers)
		mux.HandleFunc("POST "+p+"/groups/{id}/members/$ref", s.handleAddGroupMember)
		mux.HandleFunc("GET "+p+"/groups/{id}/owners", s.handleGraphOwners)
		mux.HandleFunc("POST "+p+"/groups/{id}/owners/$ref", s.handleAddOwner)
		mux.HandleFunc("PATCH "+p+"/groups/{id}", s.handlePatchGroup)
		mux.HandleFunc("GET "+p+"/applications", s.handleListApps)
		mux.HandleFunc("POST "+p+"/applications", s.handleCreateApp)
		mux.HandleFunc("GET "+p+"/applications/{appId}", s.handleGetApp)
		mux.HandleFunc("PATCH "+p+"/applications/{appId}", s.handlePatchApp)
		mux.HandleFunc("DELETE "+p+"/applications/{appId}", s.handleDeleteApp)
		mux.HandleFunc("GET "+p+"/applications/{appId}/owners", s.handleGraphOwners)
		mux.HandleFunc("POST "+p+"/applications/{appId}/owners/$ref", s.handleAddOwner)
		mux.HandleFunc("POST "+p+"/applications/{appId}/addPassword", s.handleAddPassword)
		mux.HandleFunc("POST "+p+"/applications/{appId}/addKey", s.handleAddKey)
		mux.HandleFunc("GET "+p+"/applications/{appId}/federatedIdentityCredentials", s.handleListFIC)
		mux.HandleFunc("POST "+p+"/applications/{appId}/federatedIdentityCredentials", s.handleCreateFIC)
		mux.HandleFunc("GET "+p+"/servicePrincipals", s.handleGraphSPs)
		mux.HandleFunc("GET "+p+"/servicePrincipals/{id}", s.handleGraphSP)
		mux.HandleFunc("GET "+p+"/servicePrincipals/{id}/owners", s.handleGraphOwners)
		mux.HandleFunc("POST "+p+"/servicePrincipals/{id}/owners/$ref", s.handleAddOwner)
		mux.HandleFunc("GET "+p+"/servicePrincipals/{id}/appRoleAssignedTo", s.handleAppRoleAssignedTo)
		mux.HandleFunc("POST "+p+"/servicePrincipals/{id}/addPassword", s.handleAddPassword)
		mux.HandleFunc("POST "+p+"/servicePrincipals/{id}/addKey", s.handleAddKey)
		mux.HandleFunc("GET "+p+"/devices", s.handleGraphDevices)
		mux.HandleFunc("GET "+p+"/devices/{id}", s.handleGraphDevice)
		mux.HandleFunc("PATCH "+p+"/devices/{id}", s.handlePatchDevice)
		mux.HandleFunc("GET "+p+"/devices/{id}/registeredOwners", s.handleGraphOwners)
		mux.HandleFunc("GET "+p+"/directoryRoles", s.handleGraphDirectoryRoles)
		mux.HandleFunc("GET "+p+"/directoryRoles/{id}/members", s.handleGraphRoleMembers)
		mux.HandleFunc("POST "+p+"/directoryRoles/{id}/members/$ref", s.handleAddRoleMember)
		mux.HandleFunc("GET "+p+"/roleManagement/directory/roleDefinitions", s.handleGraphRoleDefinitions)
		mux.HandleFunc("GET "+p+"/roleManagement/directory/roleAssignments", s.handleGraphRoleAssignments)
		mux.HandleFunc("GET "+p+"/roleManagement/directory/roleEligibilityScheduleInstances", s.handleGraphEmptyList)
		mux.HandleFunc("GET "+p+"/policies/roleManagementPolicyAssignments", s.handleGraphEmptyList)
		mux.HandleFunc("GET "+p+"/identity/conditionalAccess/policies", s.handleGraphCAPolicies)
		mux.HandleFunc("GET "+p+"/{path...}", s.handleGraphUnknown)
		mux.HandleFunc("POST "+p+"/{path...}", s.handleGraphUnknownPost)
	}
}

func (s *Service) requireGraph(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := authn.PrincipalFromContext(r.Context()); !ok {
		azerrors.WriteGraph(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is empty or invalid.")
		return false
	}
	return true
}

func (s *Service) handleGraphEmptyList(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	s.writeOData(w, r, []map[string]any{})
}

func (s *Service) handleGraphUnknown(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	rest := strings.Trim(r.PathValue("path"), "/")
	if strings.Contains(rest, "applications(appId=") {
		id := store.NormalizeAppIdFilter(rest)
		if id != "" {
			r.SetPathValue("appId", id)
		}
		if !strings.Contains(rest, "/") {
			s.handleGetApp(w, r)
			return
		}
		if strings.HasSuffix(rest, "/owners") {
			s.handleGraphOwners(w, r)
			return
		}
	}
	if rest == "" || !graphPathLooksLikeItem(rest) {
		s.writeOData(w, r, []map[string]any{})
		return
	}
	azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource not found")
}

func (s *Service) handleGraphUnknownPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	rest := r.PathValue("path")
	if strings.Contains(rest, "applications(appId=") {
		if id := store.NormalizeAppIdFilter(rest); id != "" {
			r.SetPathValue("appId", id)
		}
	}
	switch {
	case strings.Contains(rest, "addPassword"):
		s.handleAddPassword(w, r)
	case strings.Contains(rest, "addKey"):
		s.handleAddKey(w, r)
	case strings.Contains(rest, "owners/$ref") || strings.Contains(rest, "owners/%24ref"):
		s.handleAddOwner(w, r)
	case strings.Contains(rest, "members/$ref") || strings.Contains(rest, "members/%24ref"):
		if strings.Contains(rest, "directoryRoles") {
			s.handleAddRoleMember(w, r)
			return
		}
		s.handleAddGroupMember(w, r)
	default:
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource not found")
	}
}

func graphPathLooksLikeItem(rest string) bool {
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return false
	}
	if strings.Contains(rest, "(") {
		return true
	}
	last := rest
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		last = rest[i+1:]
	}
	return looksLikeGUID(last)
}

func looksLikeGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

func (s *Service) handleGraphOrganization(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	tid := s.appTenant()
	s.writeOData(w, r, []map[string]any{{
		"id":              tid,
		"displayName":     "Noctaxris-AZ Lab",
		"verifiedDomains": []map[string]any{{"name": "lab.local", "isDefault": true}},
	}})
}

func (s *Service) handleGraphUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	users, err := s.Store.ListDirectoryUsers(s.appTenant())
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(users))
	for _, u := range users {
		items = append(items, userJSON(u))
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	u, ok, err := s.Store.GetDirectoryUser(r.PathValue("id"))
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "User not found")
		return
	}
	writeJSON(w, http.StatusOK, userJSON(u))
}

func (s *Service) handleGraphGroups(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	groups, err := s.Store.ListDirectoryGroups(s.appTenant())
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		items = append(items, groupJSON(g))
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphGroup(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	g, ok, err := s.Store.GetDirectoryGroup(r.PathValue("id"))
	if err != nil || !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "Group not found")
		return
	}
	writeJSON(w, http.StatusOK, groupJSON(g))
}

func (s *Service) handleGraphGroupMembers(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	ids, types, err := s.Store.ListGroupMembers(r.PathValue("id"))
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(ids))
	for i, id := range ids {
		typ := "user"
		if i < len(types) {
			typ = types[i]
		}
		items = append(items, map[string]any{"id": id, "@odata.type": "#microsoft.graph." + typ})
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphOwners(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	id := r.PathValue("appId")
	if id == "" {
		id = r.PathValue("id")
	}
	obj, _, _, ok, _ := s.Store.ResolveEntraApp(s.appTenant(), id)
	if ok {
		id = obj
	}
	owners, err := s.Store.ListOwners(id)
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(owners))
	for _, oid := range owners {
		items = append(items, map[string]any{"id": oid})
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphSPs(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	list, err := s.Store.ListServicePrincipals(s.appTenant())
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(list))
	for _, sp := range list {
		items = append(items, spJSON(sp))
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphSP(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	sp, ok, err := s.Store.GetServicePrincipal(r.PathValue("id"))
	if err != nil || !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "servicePrincipal not found")
		return
	}
	writeJSON(w, http.StatusOK, spJSON(sp))
}

func (s *Service) handleAppRoleAssignedTo(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	rows, err := s.Store.ListAppRoleAssignedTo(r.PathValue("id"))
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		m := map[string]any{}
		for k, v := range row {
			m[k] = v
		}
		items = append(items, m)
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphDevices(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	list, err := s.Store.ListDevices(s.appTenant())
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(list))
	for _, d := range list {
		items = append(items, deviceJSON(d))
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	d, ok, err := s.Store.GetDevice(r.PathValue("id"))
	if err != nil || !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "Device not found")
		return
	}
	writeJSON(w, http.StatusOK, deviceJSON(d))
}

func (s *Service) handleGraphDirectoryRoles(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	roles, err := s.Store.ListDirectoryRoles(s.appTenant())
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		items = append(items, map[string]any{
			"id": role.ID, "displayName": role.DisplayName, "roleTemplateId": role.TemplateID,
		})
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphRoleMembers(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	ids, err := s.Store.ListDirectoryRoleMembers(r.PathValue("id"))
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		items = append(items, map[string]any{"id": id})
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphRoleDefinitions(w http.ResponseWriter, r *http.Request) {
	s.handleGraphDirectoryRoles(w, r)
}

func (s *Service) handleGraphRoleAssignments(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	rows, err := s.Store.ListUnifiedRoleAssignments()
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		m := map[string]any{}
		for k, v := range row {
			m[k] = v
		}
		items = append(items, m)
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleGraphCAPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	rows, err := s.Store.ListCAPolicies()
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	s.writeOData(w, r, rows)
}

func userJSON(u store.DirectoryUser) map[string]any {
	return map[string]any{
		"id": u.ID, "displayName": u.DisplayName, "userPrincipalName": u.UserPrincipalName,
		"mail": u.Mail, "department": u.Department, "jobTitle": u.JobTitle, "accountEnabled": true,
	}
}

func groupJSON(g store.DirectoryGroup) map[string]any {
	return map[string]any{
		"id": g.ID, "displayName": g.DisplayName, "mail": g.Mail, "securityEnabled": g.SecurityEnabled,
		"membershipRule": g.MembershipRule, "membershipRuleProcessingState": g.MembershipRuleProcessingState,
	}
}

func spJSON(sp store.DirectoryServicePrincipal) map[string]any {
	return map[string]any{"id": sp.ID, "appId": sp.AppID, "displayName": sp.DisplayName}
}

func deviceJSON(d store.DirectoryDevice) map[string]any {
	return map[string]any{
		"id": d.ID, "displayName": d.DisplayName, "deviceId": d.DeviceID, "operatingSystem": d.OperatingSystem,
	}
}
