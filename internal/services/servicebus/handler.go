package servicebus

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

// Handler serves Service Bus ARM and optional HTTP lab message routes.
type Handler struct {
	Store          *store.Store
	Auth           *authn.Authenticator
	Authz          *authz.Evaluator
	AMQPListenAddr string
}

// Register mounts Service Bus routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ServiceBus/namespaces/{name}", h.putNamespace)
	mux.HandleFunc("GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ServiceBus/namespaces/{name}", h.getNamespace)
	mux.HandleFunc("PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ServiceBus/namespaces/{ns}/queues/{queue}", h.putQueue)
	mux.HandleFunc("GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ServiceBus/namespaces/{ns}/queues/{queue}", h.getQueue)
	mux.HandleFunc("GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ServiceBus/namespaces/{name}/connectionString", h.connectionString)

	mux.HandleFunc("POST /servicebus/{ns}/queues/{q}/messages", h.postMessage)
	mux.HandleFunc("GET /servicebus/{ns}/queues/{q}/messages", h.getMessage)
}

func (h *Handler) putNamespace(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.ServiceBus/namespaces/write", armScope(r)) {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	name := r.PathValue("name")
	location := "eastus"
	var body struct {
		Location string `json:"location"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if body.Location != "" {
		location = body.Location
	}
	key, err := h.Store.UpsertServiceBusNamespace(sub, rg, name, location)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_ = key
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.ServiceBus/namespaces/" + name
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"name":     name,
		"type":     "Microsoft.ServiceBus/namespaces",
		"location": location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
			"serviceBusEndpoint": amqpEndpoint(h.AMQPListenAddr),
		},
	})
}

func (h *Handler) getNamespace(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.ServiceBus/namespaces/read", armScope(r)) {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	name := r.PathValue("name")
	location, ok, err := h.Store.GetServiceBusNamespace(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "namespace not found")
		return
	}
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.ServiceBus/namespaces/" + name
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"name":     name,
		"type":     "Microsoft.ServiceBus/namespaces",
		"location": location,
		"properties": map[string]any{
			"provisioningState":  "Succeeded",
			"serviceBusEndpoint": amqpEndpoint(h.AMQPListenAddr),
		},
	})
}

func (h *Handler) putQueue(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.ServiceBus/namespaces/queues/write", armScope(r)) {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	ns := r.PathValue("ns")
	queue := r.PathValue("queue")
	if _, ok, err := h.Store.GetServiceBusNamespace(sub, rg, ns); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	} else if !ok {
		azerrors.NotFound(w, "namespace not found")
		return
	}
	if err := h.Store.CreateServiceBusQueue(ns, queue); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.ServiceBus/namespaces/" + ns + "/queues/" + queue
	writeJSON(w, http.StatusOK, map[string]any{
		"id":   id,
		"name": queue,
		"type": "Microsoft.ServiceBus/namespaces/queues",
		"properties": map[string]any{
			"status": "Active",
		},
	})
}

func (h *Handler) getQueue(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.ServiceBus/namespaces/queues/read", armScope(r)) {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	ns := r.PathValue("ns")
	queue := r.PathValue("queue")
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.ServiceBus/namespaces/" + ns + "/queues/" + queue
	writeJSON(w, http.StatusOK, map[string]any{
		"id":   id,
		"name": queue,
		"type": "Microsoft.ServiceBus/namespaces/queues",
		"properties": map[string]any{
			"status": "Active",
		},
	})
}

func (h *Handler) connectionString(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.ServiceBus/namespaces/read", armScope(r)) {
		return
	}
	name := r.PathValue("name")
	key, ok, err := h.Store.GetSBNamespaceKey(name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "namespace not found")
		return
	}
	endpoint := amqpEndpoint(h.AMQPListenAddr)
	cs := "Endpoint=sb://" + strings.TrimPrefix(strings.TrimPrefix(endpoint, "amqps://"), "amqp://") +
		"/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=" + key +
		";EntityPath="
	writeJSON(w, http.StatusOK, map[string]any{
		"connectionString": cs,
		"endpoint":         endpoint,
		"note":             "AMQP 1.0 lite on " + endpoint + "; full azservicebus SDK interop is best-effort lite",
	})
}

func (h *Handler) postMessage(w http.ResponseWriter, r *http.Request) {
	if !h.requireRootOrBearer(w, r) {
		return
	}
	ns := r.PathValue("ns")
	q := r.PathValue("q")
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	if err := h.Store.EnqueueSB(ns, q, body); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "enqueued"})
}

func (h *Handler) getMessage(w http.ResponseWriter, r *http.Request) {
	if !h.requireRootOrBearer(w, r) {
		return
	}
	ns := r.PathValue("ns")
	q := r.PathValue("q")
	body, ok, err := h.Store.DequeueSB(ns, q)
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

func amqpEndpoint(addr string) string {
	if addr == "" {
		addr = "127.0.0.1:5672"
	}
	return "amqp://" + addr
}

func (h *Handler) requireRootOrBearer(w http.ResponseWriter, r *http.Request) bool {
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

func (h *Handler) requireBearerARM(w http.ResponseWriter, r *http.Request, action, scope string) bool {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	p, err := h.Auth.AuthenticateRequest(r)
	if err != nil {
		azerrors.Unauthenticated(w, "")
		return false
	}
	if h.Authz == nil {
		if p.IsRoot {
			return true
		}
		azerrors.Forbidden(w, "")
		return false
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

func armScope(r *http.Request) string {
	return "/subscriptions/" + r.PathValue("sub") + "/resourceGroups/" + r.PathValue("rg")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
