package servicebus

import (
	"io"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

func (h *Handler) putTopic(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.ServiceBus/namespaces/topics/write", armScope(r)) {
		return
	}
	ns, topic := r.PathValue("ns"), r.PathValue("topic")
	if err := h.Store.CreateServiceBusTopic(ns, topic); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": topic, "type": "Microsoft.ServiceBus/namespaces/topics",
		"properties": map[string]any{"status": "Active"},
	})
}

func (h *Handler) putSubscription(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.ServiceBus/namespaces/topics/subscriptions/write", armScope(r)) {
		return
	}
	ns, topic, subName := r.PathValue("ns"), r.PathValue("topic"), r.PathValue("subName")
	if err := h.Store.CreateServiceBusSubscription(ns, topic, subName, ""); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": subName, "type": "Microsoft.ServiceBus/namespaces/topics/subscriptions",
		"properties": map[string]any{"status": "Active"},
	})
}

func (h *Handler) postTopicMessage(w http.ResponseWriter, r *http.Request) {
	if !h.requireRootOrBearer(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	if err := h.Store.EnqueueSBTopic(r.PathValue("ns"), r.PathValue("t"), r.PathValue("s"), body); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "enqueued"})
}

func (h *Handler) getTopicMessage(w http.ResponseWriter, r *http.Request) {
	if !h.requireRootOrBearer(w, r) {
		return
	}
	body, ok, err := h.Store.DequeueSBTopic(r.PathValue("ns"), r.PathValue("t"), r.PathValue("s"))
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
