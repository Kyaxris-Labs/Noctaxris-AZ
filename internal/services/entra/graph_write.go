package entra

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

func (s *Service) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		Department string `json:"department"`
		JobTitle   string `json:"jobTitle"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	id := r.PathValue("id")
	if err := s.Store.PatchDirectoryUser(id, body.Department, body.JobTitle); err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.refreshDynamicGroups()
	u, ok, _ := s.Store.GetDirectoryUser(id)
	if !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "User not found")
		return
	}
	writeJSON(w, http.StatusOK, userJSON(u))
}

func (s *Service) handlePatchDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		DisplayName string `json:"displayName"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	id := r.PathValue("id")
	if err := s.Store.PatchDevice(id, body.DisplayName); err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.refreshDynamicGroups()
	d, ok, _ := s.Store.GetDevice(id)
	if !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "Device not found")
		return
	}
	writeJSON(w, http.StatusOK, deviceJSON(d))
}

func (s *Service) handlePatchGroup(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		MembershipRule                string `json:"membershipRule"`
		MembershipRuleProcessingState string `json:"membershipRuleProcessingState"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if err := s.Store.UpdateGroupRule(r.PathValue("id"), body.MembershipRule, body.MembershipRuleProcessingState); err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	s.refreshDynamicGroups()
	g, ok, _ := s.Store.GetDirectoryGroup(r.PathValue("id"))
	if !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "Group not found")
		return
	}
	writeJSON(w, http.StatusOK, groupJSON(g))
}

func (s *Service) handleAddOwner(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		ODataID string `json:"@odata.id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	ownerID := body.ODataID
	if i := strings.LastIndex(ownerID, "/"); i >= 0 {
		ownerID = ownerID[i+1:]
	}
	if ownerID == "" {
		azerrors.WriteGraph(w, http.StatusBadRequest, "BadRequest", "@odata.id is required")
		return
	}
	resourceID, ok := s.ownerTarget(r)
	if !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource not found")
		return
	}
	if err := s.Store.AddOwner(resourceID, ownerID, "user"); err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleAddRoleMember(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		ODataID string `json:"@odata.id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	memberID := body.ODataID
	if i := strings.LastIndex(memberID, "/"); i >= 0 {
		memberID = memberID[i+1:]
	}
	if memberID == "" {
		azerrors.WriteGraph(w, http.StatusBadRequest, "BadRequest", "@odata.id is required")
		return
	}
	roleID := r.PathValue("id")
	if roleID == "" {
		roleID = segmentAfter(r.URL.Path, "/directoryRoles/")
	}
	if err := s.Store.AddDirectoryRoleMember(roleID, memberID); err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleAddGroupMember(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		ODataID string `json:"@odata.id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	memberID := body.ODataID
	if i := strings.LastIndex(memberID, "/"); i >= 0 {
		memberID = memberID[i+1:]
	}
	if memberID == "" {
		azerrors.WriteGraph(w, http.StatusBadRequest, "BadRequest", "@odata.id is required")
		return
	}
	groupID := r.PathValue("id")
	if groupID == "" {
		groupID = segmentAfter(r.URL.Path, "/groups/")
	}
	if err := s.Store.AddGroupMember(groupID, memberID, "user"); err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleAddPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		PasswordCredential struct {
			DisplayName string `json:"displayName"`
		} `json:"passwordCredential"`
		DisplayName string `json:"displayName"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	display := body.DisplayName
	if display == "" {
		display = body.PasswordCredential.DisplayName
	}
	resourceID, resourceType := s.passwordTarget(r)
	if resourceID == "" {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "application not found")
		return
	}
	secret := store.RandomToken(20)
	id, err := s.Store.AddPassword(resourceID, resourceType, display, authn.HashToken(secret), store.HintFromSecret(secret))
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	now := s.now()
	writeJSON(w, http.StatusOK, map[string]any{
		"keyId":         id,
		"secretText":    secret,
		"hint":          store.HintFromSecret(secret),
		"displayName":   display,
		"startDateTime": now.Format(time.RFC3339Nano),
		"endDateTime":   now.Add(365 * 24 * time.Hour).Format(time.RFC3339Nano),
	})
}

func graphPathObjectID(r *http.Request) string {
	raw := r.PathValue("appId")
	if raw == "" {
		raw = r.PathValue("id")
	}
	raw = store.NormalizeAppIdFilter(raw)
	if raw != "" && !strings.Contains(raw, "/") && !strings.Contains(raw, "(") {
		return raw
	}
	if id := store.NormalizeAppIdFilter(r.PathValue("path")); id != "" && id != r.PathValue("path") {
		return id
	}
	if id := store.NormalizeAppIdFilter(r.URL.Path); id != "" && id != r.URL.Path {
		return id
	}
	for _, marker := range []string{"/applications/", "/servicePrincipals/", "/groups/", "/directoryRoles/"} {
		if id := segmentAfter(r.URL.Path, marker); id != "" {
			return id
		}
	}
	return raw
}

func segmentAfter(path, marker string) string {
	i := strings.Index(path, marker)
	if i < 0 {
		return ""
	}
	rest := path[i+len(marker):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return store.NormalizeAppIdFilter(rest)
}

func (s *Service) ownerTarget(r *http.Request) (string, bool) {
	path := r.URL.Path
	raw := graphPathObjectID(r)
	if raw == "" {
		return "", false
	}
	switch {
	case strings.Contains(path, "/servicePrincipals/") || strings.Contains(path, "/servicePrincipals("):
		if strings.Contains(path, "servicePrincipals(appId=") {
			sp, ok, _ := s.Store.GetServicePrincipal(raw)
			if !ok {
				return "", false
			}
			return sp.ID, true
		}
		sp, ok, _ := s.Store.GetServicePrincipal(raw)
		if !ok || sp.ID != raw {
			return "", false
		}
		return sp.ID, true
	case strings.Contains(path, "/applications/") || strings.Contains(path, "/applications("):
		if strings.Contains(path, "applications(appId=") {
			obj, _, _, ok, _ := s.Store.ResolveEntraApp(s.appTenant(), raw)
			return obj, ok
		}
		row, ok, _ := s.Store.GetEntraApp(s.appTenant(), raw)
		if !ok || row.ObjectID == "" || row.ObjectID != raw {
			return "", false
		}
		return row.ObjectID, true
	case strings.Contains(path, "/groups/"):
		return raw, true
	case strings.Contains(path, "/devices/"):
		return raw, true
	default:
		return "", false
	}
}

func (s *Service) passwordTarget(r *http.Request) (id, typ string) {
	path := r.URL.Path
	raw := graphPathObjectID(r)
	if strings.Contains(path, "/servicePrincipals/") {
		sp, ok, _ := s.Store.GetServicePrincipal(raw)
		if !ok {
			return "", "servicePrincipal"
		}
		return sp.ID, "servicePrincipal"
	}
	obj, _, _, ok, _ := s.Store.ResolveEntraApp(s.appTenant(), raw)
	if !ok {
		filter := store.NormalizeAppIdFilter(r.PathValue("path"))
		if filter != "" {
			obj, _, _, ok, _ = s.Store.ResolveEntraApp(s.appTenant(), filter)
		}
	}
	if !ok {
		return "", "application"
	}
	return obj, "application"
}

func (s *Service) handleAddKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		KeyCredential map[string]any `json:"keyCredential"`
		Proof         string         `json:"proof"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	resourceID, resourceType := s.passwordTarget(r)
	if resourceID == "" {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "application not found")
		return
	}
	n, err := s.Store.CountKeyCredentials(resourceID)
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if n > 0 {
		if !s.validAddKeyProof(body.Proof, resourceID) {
			azerrors.WriteGraph(w, http.StatusBadRequest, "BadRequest", "proof JWT is required when a key credential already exists")
			return
		}
	}
	keyPEM := ""
	if body.KeyCredential != nil {
		if v, ok := body.KeyCredential["key"].(string); ok {
			keyPEM = v
		}
	}
	id, err := s.Store.AddKeyCredential(resourceID, resourceType, keyPEM, "Verify", "AsymmetricX509Cert")
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "type": "AsymmetricX509Cert", "usage": "Verify"})
}

func (s *Service) validAddKeyProof(proof, objectID string) bool {
	pems, err := s.Store.ListKeyPEMs(objectID)
	if err != nil || len(pems) == 0 {
		return false
	}
	var claims map[string]any
	verified := false
	for _, pemBytes := range pems {
		pub, perr := parseRSAPublicPEM([]byte(pemBytes))
		if perr != nil {
			continue
		}
		c, verr := authn.VerifyRS256JWT(pub, proof, s.now())
		if verr != nil {
			continue
		}
		claims = c
		verified = true
		break
	}
	if !verified {
		return false
	}
	audOK := false
	for _, a := range authn.ClaimAudiences(claims) {
		if a == authn.AudienceAADGraphAppID {
			audOK = true
			break
		}
	}
	if !audOK {
		return false
	}
	if authn.ClaimString(claims, "iss") != objectID {
		return false
	}
	nbf, nbfOK := authn.ClaimUnix(claims, "nbf")
	exp, expOK := authn.ClaimUnix(claims, "exp")
	if !nbfOK || !expOK {
		return false
	}
	now := s.now().Unix()
	return now >= nbf && now <= exp
}

func (s *Service) handleListFIC(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	obj, _, _, ok, _ := s.Store.ResolveEntraApp(s.appTenant(), r.PathValue("appId"))
	if !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "application not found")
		return
	}
	list, err := s.Store.ListFICs(obj)
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(list))
	for _, f := range list {
		items = append(items, map[string]any{
			"id": f.ID, "name": f.Name, "issuer": f.Issuer, "subject": f.Subject, "audiences": f.Audiences,
		})
	}
	s.writeOData(w, r, items)
}

func (s *Service) handleCreateFIC(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body struct {
		Name                     string   `json:"name"`
		Issuer                   string   `json:"issuer"`
		Subject                  string   `json:"subject"`
		Audiences                []string `json:"audiences"`
		ClaimsMatchingExpression string   `json:"claimsMatchingExpression"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	obj, _, _, ok, _ := s.Store.ResolveEntraApp(s.appTenant(), r.PathValue("appId"))
	if !ok {
		azerrors.WriteGraph(w, http.StatusNotFound, "Request_ResourceNotFound", "application not found")
		return
	}
	if body.Issuer == "" || body.Subject == "" {
		azerrors.WriteGraph(w, http.StatusBadRequest, "BadRequest", "issuer and subject are required")
		return
	}
	f, err := s.Store.CreateFIC(obj, body.Name, body.Issuer, body.Subject, body.Audiences, body.ClaimsMatchingExpression)
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": f.ID, "name": f.Name, "issuer": f.Issuer, "subject": f.Subject, "audiences": f.Audiences,
	})
}

func (s *Service) refreshDynamicGroups() {
	groups, err := s.Store.ListDirectoryGroups(s.appTenant())
	if err != nil {
		return
	}
	users, _ := s.Store.ListDirectoryUsers(s.appTenant())
	devices, _ := s.Store.ListDevices(s.appTenant())
	for _, g := range groups {
		rule := strings.TrimSpace(g.MembershipRule)
		if rule == "" {
			continue
		}
		if strings.Contains(strings.ToLower(rule), "user.") {
			for _, u := range users {
				if matchDirectoryRule(rule, "user", u.Department, u.JobTitle, u.DisplayName) {
					_ = s.Store.AddGroupMember(g.ID, u.ID, "user")
				}
			}
		}
		if strings.Contains(strings.ToLower(rule), "device.") {
			for _, d := range devices {
				if matchDirectoryRule(rule, "device", "", "", d.DisplayName) {
					_ = s.Store.AddGroupMember(g.ID, d.ID, "device")
				}
			}
		}
	}
}

func matchDirectoryRule(rule, kind, department, jobTitle, displayName string) bool {
	lower := strings.ToLower(rule)
	if strings.Contains(lower, "serviceprincipal") {
		return false
	}
	eq := func(attr, want, have string) bool {
		return strings.Contains(lower, kind+"."+attr+" -eq") && strings.Contains(strings.ToLower(have), strings.ToLower(strings.Trim(want, `"' `)))
	}
	if strings.Contains(lower, kind+".department -eq") {
		want := extractQuoted(rule, "department")
		return eq("department", want, department) || strings.EqualFold(department, want)
	}
	if strings.Contains(lower, kind+".jobtitle -eq") {
		want := extractQuoted(rule, "jobTitle")
		if want == "" {
			want = extractQuoted(rule, "jobtitle")
		}
		return strings.EqualFold(jobTitle, want)
	}
	if strings.Contains(lower, kind+".displayname -eq") {
		want := extractQuoted(rule, "displayName")
		if want == "" {
			want = extractQuoted(rule, "displayname")
		}
		return strings.EqualFold(displayName, want)
	}
	return false
}

func extractQuoted(rule, attr string) string {
	idx := strings.Index(strings.ToLower(rule), strings.ToLower(attr))
	if idx < 0 {
		return ""
	}
	rest := rule[idx:]
	q := strings.IndexAny(rest, `"'`)
	if q < 0 {
		return ""
	}
	quote := rest[q]
	rest = rest[q+1:]
	end := strings.IndexByte(rest, quote)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
