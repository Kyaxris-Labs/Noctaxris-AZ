package openai

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

var allowedModels = map[string]struct{}{
	"gpt-4o-mini":   {},
	"gpt-35-turbo":  {},
	"gpt-3.5-turbo": {},
}

func (h *Handler) chatCompletions(w http.ResponseWriter, r *http.Request) {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return
	}
	if _, err := h.Auth.AuthenticateRequest(r); err != nil {
		azerrors.Unauthenticated(w, "")
		return
	}
	name := r.PathValue("name")
	if _, ok, err := h.Store.GetProviderResourceByName(providerKey, name); err != nil || !ok {
		azerrors.NotFound(w, "account not found")
		return
	}
	var body struct {
		Model    string `json:"model"`
		Messages []any  `json:"messages"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	model := strings.TrimSpace(body.Model)
	if _, ok := allowedModels[model]; !ok {
		azerrors.BadRequest(w, "model not allowlisted")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "chatcmpl-lab",
		"object":  "chat.completion",
		"model":   model,
		"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": "noctaxris-az canned response"}, "finish_reason": "stop"}},
	})
}
