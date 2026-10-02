package eventhubs

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/azauth"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

// Handler serves Event Hubs ARM + HTTP message lab.
type Handler struct {
	Store *store.Store
	Auth  *authn.Authenticator
	Authz *authz.Evaluator
}

// Register mounts routes.
func (h *Handler) Register(mux *http.ServeMux) {
	base := "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.EventHub/namespaces"
	mux.HandleFunc("PUT "+base+"/{name}", h.putNS)
	mux.HandleFunc("GET "+base+"/{name}", h.getNS)
	mux.HandleFunc("PUT "+base+"/{ns}/eventhubs/{hub}", h.putHub)
	mux.HandleFunc("PUT "+base+"/{ns}/eventhubs/{hub}/consumergroups/{cg}", h.putCG)
	mux.HandleFunc("POST /eventhubs/{ns}/hubs/{hub}/messages", h.postMsg)
	mux.HandleFunc("GET /eventhubs/{ns}/hubs/{hub}/messages", h.getMsg)
	mux.HandleFunc("GET /eventhubs/{ns}/hubs/{hub}/capturedEvents/{id}", h.getCapturedEvent)
	mux.HandleFunc("GET /eventhubs/{ns}/hubs/{hub}/capturedEvents", h.capturedEvents)
}

func (h *Handler) putNS(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.EventHub/namespaces/write") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	location := "eastus"
	var body struct {
		Location string `json:"location"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if body.Location != "" {
		location = body.Location
	}
	if err := h.Store.UpsertEventHubsNamespace(sub, rg, name, location); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":   "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.EventHub/namespaces/" + name,
		"name": name, "type": "Microsoft.EventHub/namespaces", "location": location,
		"properties": map[string]any{"provisioningState": "Succeeded"},
	})
}

func (h *Handler) getNS(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.EventHub/namespaces/read") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	location, ok, err := h.Store.GetEventHubsNamespace(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "namespace not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":   "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.EventHub/namespaces/" + name,
		"name": name, "type": "Microsoft.EventHub/namespaces", "location": location,
		"properties": map[string]any{"provisioningState": "Succeeded"},
	})
}

func (h *Handler) putHub(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.EventHub/namespaces/eventhubs/write") {
		return
	}
	sub, rg, ns, hub := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("ns"), r.PathValue("hub")
	if _, ok, err := h.Store.GetEventHubsNamespace(sub, rg, ns); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	} else if !ok {
		azerrors.NotFound(w, "namespace not found")
		return
	}
	key := store.EventHubNamespaceKey(sub, rg, ns)
	if err := h.Store.CreateEventHub(key, hub, 2); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": hub, "type": "Microsoft.EventHub/namespaces/eventhubs",
		"properties": map[string]any{"partitionCount": 2, "status": "Active"},
	})
}

func (h *Handler) putCG(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.EventHub/namespaces/eventhubs/consumergroups/write") {
		return
	}
	sub, rg, ns := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("ns")
	if _, ok, err := h.Store.GetEventHubsNamespace(sub, rg, ns); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	} else if !ok {
		azerrors.NotFound(w, "namespace not found")
		return
	}
	key := store.EventHubNamespaceKey(sub, rg, ns)
	if err := h.Store.CreateEventHubConsumerGroup(key, r.PathValue("hub"), r.PathValue("cg")); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": r.PathValue("cg"), "type": "Microsoft.EventHub/namespaces/eventhubs/consumergroups"})
}

func (h *Handler) postMsg(w http.ResponseWriter, r *http.Request) {
	key, ok := h.requireMessageDataPlane(w, r, "Microsoft.EventHub/namespaces/eventhubs/send/action")
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	part := r.URL.Query().Get("partition")
	if err := h.Store.EnqueueEventHub(key, r.PathValue("hub"), part, body); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "enqueued"})
}

func (h *Handler) getMsg(w http.ResponseWriter, r *http.Request) {
	key, ok := h.requireMessageDataPlane(w, r, "Microsoft.EventHub/namespaces/eventhubs/receive/action")
	if !ok {
		return
	}
	body, found, err := h.Store.DequeueEventHub(key, r.PathValue("hub"), r.URL.Query().Get("partition"))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !found {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *Handler) capturedEvents(w http.ResponseWriter, r *http.Request) {
	keys, ok := h.requireCaptureRead(w, r)
	if !ok {
		return
	}
	list, err := h.Store.ListEventHubCapturedForNamespaces(keys, r.PathValue("hub"))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	value := make([]any, 0, len(list))
	for _, ev := range list {
		value = append(value, capturedEventJSON(ev))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (h *Handler) getCapturedEvent(w http.ResponseWriter, r *http.Request) {
	keys, ok := h.requireCaptureRead(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		azerrors.BadRequest(w, "captured event id must be a positive integer")
		return
	}
	ev, found, err := h.Store.GetEventHubCapturedForNamespaces(keys, r.PathValue("hub"), id)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !found {
		azerrors.NotFound(w, "captured event not found")
		return
	}
	writeJSON(w, http.StatusOK, capturedEventJSON(ev))
}

func capturedEventJSON(ev store.EventHubCapturedEvent) map[string]any {
	return map[string]any{
		"id":           ev.ID,
		"partitionId":  ev.PartitionID,
		"enqueuedTime": ev.InsertedAt,
		"body":         string(ev.Body),
	}
}

func (h *Handler) requireCaptureRead(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	// Authenticate and audience before namespace lookup so missing Bearer stays 401.
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return nil, false
	}
	p, err := h.Auth.AuthenticateRequest(r)
	if err != nil {
		azerrors.Unauthenticated(w, "")
		return nil, false
	}
	if !p.AllowsEventHubs() {
		azerrors.InvalidAuthenticationTokenAudience(w, "")
		return nil, false
	}
	ns := r.PathValue("ns")
	rows, err := h.Store.ListEventHubsNamespacesByName(ns)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return nil, false
	}
	if len(rows) == 0 {
		azerrors.Forbidden(w, "")
		return nil, false
	}
	if p.IsRoot {
		keys := make([]string, 0, len(rows))
		for _, row := range rows {
			keys = append(keys, store.EventHubNamespaceKey(row.SubscriptionID, row.ResourceGroup, row.Name))
		}
		return keys, true
	}
	if h.Authz == nil {
		azerrors.Forbidden(w, "")
		return nil, false
	}
	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		rowScope := "/subscriptions/" + row.SubscriptionID + "/resourceGroups/" + row.ResourceGroup
		allowed, err := h.Authz.Evaluate(p.ID, p.IsRoot, "Microsoft.EventHub/namespaces/eventhubs/receive/action", rowScope)
		if err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
			return nil, false
		}
		if allowed {
			keys = append(keys, store.EventHubNamespaceKey(row.SubscriptionID, row.ResourceGroup, row.Name))
		}
	}
	if len(keys) == 0 {
		azerrors.Forbidden(w, "")
		return nil, false
	}
	return keys, true
}

// requireMessageDataPlane authenticates Bearer, checks Event Hubs audience, then
// evaluates dedicated send/receive data actions. Fail-closed when Authz is nil.
// Authn/audience run before namespace lookup so missing Bearer stays 401.
func (h *Handler) requireMessageDataPlane(w http.ResponseWriter, r *http.Request, action string) (string, bool) {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return "", false
	}
	p, err := h.Auth.AuthenticateRequest(r)
	if err != nil {
		azerrors.Unauthenticated(w, "")
		return "", false
	}
	if !p.AllowsEventHubs() {
		azerrors.InvalidAuthenticationTokenAudience(w, "")
		return "", false
	}
	if !p.IsRoot && h.Authz == nil {
		azerrors.Forbidden(w, "")
		return "", false
	}
	ns := r.PathValue("ns")
	rows, err := h.Store.ListEventHubsNamespacesByName(ns)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return "", false
	}
	if len(rows) == 0 {
		azerrors.NotFound(w, "namespace not found")
		return "", false
	}
	if p.IsRoot {
		if len(rows) != 1 {
			azerrors.NotFound(w, "namespace not found")
			return "", false
		}
		return store.EventHubNamespaceKey(rows[0].SubscriptionID, rows[0].ResourceGroup, rows[0].Name), true
	}
	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		rowScope := "/subscriptions/" + row.SubscriptionID + "/resourceGroups/" + row.ResourceGroup
		allowed, err := h.Authz.Evaluate(p.ID, p.IsRoot, action, rowScope)
		if err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
			return "", false
		}
		if allowed {
			keys = append(keys, store.EventHubNamespaceKey(row.SubscriptionID, row.ResourceGroup, row.Name))
		}
	}
	if len(keys) == 0 {
		azerrors.Forbidden(w, "")
		return "", false
	}
	if len(keys) != 1 {
		// Bare HTTP paths are ambiguous when the same namespace name exists in multiple RGs.
		azerrors.NotFound(w, "namespace not found")
		return "", false
	}
	return keys[0], true
}

func (h *Handler) require(w http.ResponseWriter, r *http.Request, action string) bool {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	p, err := h.Auth.AuthenticateRequest(r)
	if err != nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	if !p.AllowsARM() {
		azerrors.InvalidAuthenticationTokenAudience(w, "")
		return false
	}
	scope := "/subscriptions/" + r.PathValue("sub") + "/resourceGroups/" + r.PathValue("rg")
	if !azauth.RequireAuthzEvaluator(w, p.IsRoot, h.Authz) {
		return false
	}
	if h.Authz == nil {
		return true
	}
	ok, err := h.Authz.Evaluate(p.ID, p.IsRoot, action, scope)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return false
	}
	if !ok {
		azerrors.Forbidden(w, "")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
