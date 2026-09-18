package entra

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

const caBlockedDescription = "AADSTS53003: Access has been blocked by Conditional Access policies. The access policy does not allow token issuance. BlockedByConditionalAccess."

func (s *Service) handleCreateCAPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireGraph(w, r) {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		azerrors.WriteGraph(w, http.StatusBadRequest, "BadRequest", "invalid JSON body")
		return
	}
	id, _ := body["id"].(string)
	display, _ := body["displayName"].(string)
	if display == "" {
		display = "lab-ca-policy"
	}
	state, _ := body["state"].(string)
	if state == "" {
		state = "enabled"
	}
	enabled := strings.EqualFold(state, "enabled")
	cond := body["conditions"]
	if cond == nil {
		cond = body
	}
	raw, err := json.Marshal(cond)
	if err != nil {
		azerrors.WriteGraph(w, http.StatusBadRequest, "BadRequest", "conditions are required")
		return
	}
	id, err = s.Store.UpsertCAPolicy(id, display, string(raw), enabled)
	if err != nil {
		azerrors.WriteGraph(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "displayName": display, "state": state, "conditions": cond,
	})
}

func (s *Service) writeConditionalAccessDenied(w http.ResponseWriter) {
	azerrors.WriteOAuth(w, http.StatusBadRequest, "invalid_grant", caBlockedDescription)
}

func (s *Service) conditionalAccessBlocked(r *http.Request, clientID string) bool {
	if s == nil || s.Store == nil {
		return false
	}
	policies, err := s.Store.ListCAPolicies()
	if err != nil || len(policies) == 0 {
		return false
	}
	ua := ""
	if r != nil {
		ua = r.Header.Get("User-Agent")
	}
	sawEnabled := false
	applied := false
	for _, p := range policies {
		state, _ := p["state"].(string)
		if !strings.EqualFold(state, "enabled") {
			continue
		}
		sawEnabled = true
		cond, _ := p["conditions"].(map[string]any)
		if cond == nil {
			continue
		}
		if caClientExcluded(cond, clientID) {
			continue
		}
		if !caClientIncluded(cond, clientID) {
			continue
		}
		applied = true
		if !caUserAgentAllowed(cond, ua) {
			return true
		}
	}
	return sawEnabled && !applied
}

func caClientIncluded(cond map[string]any, clientID string) bool {
	apps := nestedMap(cond, "applications")
	include := stringList(apps["includeApplications"])
	if len(include) == 0 {
		return false
	}
	for _, id := range include {
		if strings.EqualFold(id, "All") || strings.EqualFold(id, "AllApplications") {
			return true
		}
		if id == clientID {
			return true
		}
	}
	return false
}

func caClientExcluded(cond map[string]any, clientID string) bool {
	apps := nestedMap(cond, "applications")
	for _, id := range stringList(apps["excludeApplications"]) {
		if id == clientID {
			return true
		}
	}
	return false
}

func caUserAgentAllowed(cond map[string]any, ua string) bool {
	var prefixes []string
	switch v := cond["userAgents"].(type) {
	case map[string]any:
		prefixes = append(prefixes, stringList(v["include"])...)
	case []any:
		prefixes = append(prefixes, stringList(v)...)
	}
	known := map[string]struct{}{
		"all": {}, "browser": {}, "mobileappsanddesktopclients": {},
		"exchangeactivesync": {}, "other": {},
	}
	for _, t := range stringList(cond["clientAppTypes"]) {
		if _, ok := known[strings.ToLower(t)]; ok {
			continue
		}
		prefixes = append(prefixes, t)
	}
	if len(prefixes) == 0 {
		return true
	}
	if ua == "" {
		return false
	}
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if ua == p || strings.HasPrefix(ua, p) {
			return true
		}
	}
	return false
}

func nestedMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		var out []string
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		return []string{s}
	default:
		return nil
	}
}
