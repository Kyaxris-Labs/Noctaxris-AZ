package openai

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/azauth"
)

var allowedModels = map[string]struct{}{
	"gpt-4o-mini":   {},
	"gpt-35-turbo":  {},
	"gpt-3.5-turbo": {},
}

func (h *Handler) chatCompletions(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	row, exists, err := h.Store.GetProviderResourceByName(providerKey, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	scope := "/subscriptions/" + config.DefaultSubscriptionID +
		"/providers/Microsoft.CognitiveServices/accounts/" + name
	if exists {
		scope = "/subscriptions/" + row.SubscriptionID + "/resourceGroups/" + row.ResourceGroup +
			"/providers/Microsoft.CognitiveServices/accounts/" + name
	}
	if _, ok := azauth.RequireDataPlaneBearer(w, r, h.Auth, h.Authz, authn.Principal.AllowsCognitive,
		"Microsoft.CognitiveServices/accounts/deployments/chat/completions/action", scope); !ok {
		return
	}
	if !exists {
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
