package eventhubs

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
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
	ns, hub := r.PathValue("ns"), r.PathValue("hub")
	if err := h.Store.CreateEventHub(ns, hub, 2); err != nil {
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
	if err := h.Store.CreateEventHubConsumerGroup(r.PathValue("ns"), r.PathValue("hub"), r.PathValue("cg")); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": r.PathValue("cg"), "type": "Microsoft.EventHub/namespaces/eventhubs/consumergroups"})
}

func (h *Handler) postMsg(w http.ResponseWriter, r *http.Request) {
	if !h.requireRoot(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	part := r.URL.Query().Get("partition")
	if err := h.Store.EnqueueEventHub(r.PathValue("ns"), r.PathValue("hub"), part, body); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "enqueued"})
}

func (h *Handler) getMsg(w http.ResponseWriter, r *http.Request) {
	if !h.requireRoot(w, r) {
		return
	}
	body, ok, err := h.Store.DequeueEventHub(r.PathValue("ns"), r.PathValue("hub"), r.URL.Query().Get("partition"))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *Handler) capturedEvents(w http.ResponseWriter, r *http.Request) {
	if !h.requireRoot(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": []any{}})
}

func (h *Handler) requireRoot(w http.ResponseWriter, r *http.Request) bool {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	if _, err := h.Auth.AuthenticateRequest(r); err != nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	return true
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
	scope := "/subscriptions/" + r.PathValue("sub") + "/resourceGroups/" + r.PathValue("rg")
	if h.Authz == nil {
		return p.IsRoot
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
