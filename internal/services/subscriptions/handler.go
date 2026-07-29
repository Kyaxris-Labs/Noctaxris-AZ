package subscriptions

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

// Service serves ARM subscription and resource group APIs.
type Service struct {
	Store          *store.Store
	Authz          *authz.Evaluator
	PrincipalFrom  func(context.Context) (authn.Principal, bool)
	SubscriptionID string
}

// Mount registers ARM subscription and resource group routes.
func (s *Service) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /subscriptions/{subscriptionId}", s.getSubscription)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/resources", s.listResources)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/providers", s.listProviders)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}", s.getResourceGroup)
	mux.HandleFunc("PUT /subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}", s.putResourceGroup)
	mux.HandleFunc("GET /subscriptions/{subscriptionId}/resourcegroups", s.listResourceGroups)
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

func (s *Service) getSubscription(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	scope := "/subscriptions/" + subID
	if _, ok := s.require(w, r, "Microsoft.Resources/subscriptions/read", scope); !ok {
		return
	}
	displayName, state, tenantID, ok, err := s.Store.GetSubscription(subID)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "Subscription not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             "/subscriptions/" + subID,
		"subscriptionId": subID,
		"displayName":    displayName,
		"state":          state,
		"tenantId":       tenantID,
	})
}

func (s *Service) getResourceGroup(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	name := r.PathValue("resourceGroupName")
	scope := "/subscriptions/" + subID + "/resourceGroups/" + name
	if _, ok := s.require(w, r, "Microsoft.Resources/subscriptions/resourceGroups/read", scope); !ok {
		return
	}
	location, ok, err := s.Store.GetResourceGroup(subID, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "Resource group '"+name+"' could not be found.")
		return
	}
	writeJSON(w, http.StatusOK, resourceGroupJSON(subID, name, location))
}

func (s *Service) putResourceGroup(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	name := r.PathValue("resourceGroupName")
	scope := "/subscriptions/" + subID + "/resourceGroups/" + name
	p, ok := s.require(w, r, "Microsoft.Resources/subscriptions/resourceGroups/write", scope)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, "unable to read body")
		return
	}
	var req struct {
		Location string `json:"location"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			azerrors.BadRequest(w, "invalid JSON body")
			return
		}
	}
	location := strings.TrimSpace(req.Location)
	if location == "" {
		azerrors.BadRequest(w, "location is required")
		return
	}
	if err := s.Store.UpsertResourceGroup(subID, name, location); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	_ = s.Store.AppendActivityLog(p.ID, "Microsoft.Resources/subscriptions/resourceGroups/write", scope, "Succeeded", "")
	writeJSON(w, http.StatusOK, resourceGroupJSON(subID, name, location))
}

func (s *Service) listResourceGroups(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	scope := "/subscriptions/" + subID
	if _, ok := s.require(w, r, "Microsoft.Resources/subscriptions/resourceGroups/read", scope); !ok {
		return
	}
	list, err := s.Store.ListResourceGroups(subID)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(list))
	for _, rg := range list {
		value = append(value, resourceGroupJSON(subID, rg.Name, rg.Location))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) listResources(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	scope := "/subscriptions/" + subID
	if _, ok := s.require(w, r, "Microsoft.Resources/resources/read", scope); !ok {
		return
	}
	rgs, err := s.Store.ListResourceGroups(subID)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(rgs))
	for _, rg := range rgs {
		value = append(value, resourceGroupJSON(subID, rg.Name, rg.Location))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (s *Service) listProviders(w http.ResponseWriter, r *http.Request) {
	if !requireAPIVersion(w, r) {
		return
	}
	subID := r.PathValue("subscriptionId")
	scope := "/subscriptions/" + subID
	if _, ok := s.require(w, r, "Microsoft.Resources/providers/read", scope); !ok {
		return
	}
	providers := []map[string]any{
		{"namespace": "Microsoft.Storage", "registrationState": "Registered"},
		{"namespace": "Microsoft.KeyVault", "registrationState": "Registered"},
		{"namespace": "Microsoft.Authorization", "registrationState": "Registered"},
		{"namespace": "Microsoft.ManagedIdentity", "registrationState": "Registered"},
		{"namespace": "Microsoft.ServiceBus", "registrationState": "Registered"},
		{"namespace": "Microsoft.Web", "registrationState": "Registered"},
		{"namespace": "Microsoft.AppConfiguration", "registrationState": "Registered"},
		{"namespace": "Microsoft.Insights", "registrationState": "Registered"},
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": providers})
}

func resourceGroupJSON(subID, name, location string) map[string]any {
	return map[string]any{
		"id":       "/subscriptions/" + subID + "/resourceGroups/" + name,
		"name":     name,
		"type":     "Microsoft.Resources/resourceGroups",
		"location": location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
		},
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
