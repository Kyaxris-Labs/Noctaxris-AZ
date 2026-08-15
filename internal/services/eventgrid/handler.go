package eventgrid

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/httpegress"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

// Handler serves Event Grid ARM + publish.
type Handler struct {
	Store *store.Store
	Auth  *authn.Authenticator
	Authz *authz.Evaluator
}

// Register mounts routes.
func (h *Handler) Register(mux *http.ServeMux) {
	base := "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.EventGrid/topics"
	mux.HandleFunc("PUT "+base+"/{name}", h.putTopic)
	mux.HandleFunc("GET "+base+"/{name}", h.getTopic)
	mux.HandleFunc("PUT "+base+"/{topic}/providers/Microsoft.EventGrid/eventSubscriptions/{name}", h.putSub)
	mux.HandleFunc("POST /eventgrid/{topic}/api/events", h.publish)
}

func (h *Handler) putTopic(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.EventGrid/topics/write") {
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
	if err := h.Store.UpsertEventGridTopic(sub, rg, name, location); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.EventGrid/topics/" + name,
		"name": name, "type": "Microsoft.EventGrid/topics", "location": location,
		"properties": map[string]any{"provisioningState": "Succeeded"},
	})
}

func (h *Handler) getTopic(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.EventGrid/topics/read") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	_, _, location, ok, err := h.Store.GetEventGridTopicByName(name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "topic not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.EventGrid/topics/" + name,
		"name": name, "type": "Microsoft.EventGrid/topics", "location": location,
		"properties": map[string]any{"provisioningState": "Succeeded"},
	})
}

func (h *Handler) putSub(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.EventGrid/eventSubscriptions/write") {
		return
	}
	topic, name := r.PathValue("topic"), r.PathValue("name")
	var body struct {
		Properties struct {
			Destination struct {
				EndpointType string `json:"endpointType"`
				Properties   struct {
					EndpointURL string `json:"endpointUrl"`
				} `json:"properties"`
			} `json:"destination"`
		} `json:"properties"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	dest := body.Properties.Destination.Properties.EndpointURL
	if err := h.Store.UpsertEventGridSubscription(topic, name, dest, "{}"); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "type": "Microsoft.EventGrid/eventSubscriptions"})
}

func (h *Handler) publish(w http.ResponseWriter, r *http.Request) {
	if !h.requireRoot(w, r) {
		return
	}
	topic := r.PathValue("topic")
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	subs, err := h.Store.ListEventGridSubscriptions(topic)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	delivered := false
	for _, sub := range subs {
		if sub.DestinationURL == "" {
			continue
		}
		if err := httpegress.Allowed(sub.DestinationURL); err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, sub.DestinationURL, bytes.NewReader(raw))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 5 * time.Second}
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
			delivered = true
		}
	}
	_ = h.Store.InsertEventGridEvent(topic, string(raw), delivered)
	writeJSON(w, http.StatusOK, map[string]any{"delivered": delivered})
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
