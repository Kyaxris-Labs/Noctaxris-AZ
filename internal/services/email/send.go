package email

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
)

func (h *Handler) sendEmail(w http.ResponseWriter, r *http.Request) {
	if h.Auth == nil {
		azerrors.Unauthenticated(w, "")
		return
	}
	if _, err := h.Auth.AuthenticateRequest(r); err != nil {
		azerrors.Unauthenticated(w, "")
		return
	}
	var body struct {
		SenderAddress string `json:"senderAddress"`
		Content       struct {
			Subject string `json:"subject"`
			PlainText string `json:"plainText"`
		} `json:"content"`
		Recipients struct {
			To []struct {
				Address string `json:"address"`
			} `json:"to"`
		} `json:"recipients"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	to := ""
	if len(body.Recipients.To) > 0 {
		to = body.Recipients.To[0].Address
	}
	if err := h.Store.CaptureEmail("default", to, body.Content.Subject, body.Content.PlainText); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": "email-lab", "status": "Captured"})
}
