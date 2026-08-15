package keyvault

import (
	"encoding/json"
	"io"
	"net/http"
)

func (h *Handler) putCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireDataPlaneBearer(w, r) {
		return
	}
	vault, name := r.PathValue("vault"), r.PathValue("name")
	var body struct {
		Value  string         `json:"value"`
		Policy map[string]any `json:"policy"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	pem := []byte(body.Value)
	if len(pem) == 0 {
		pem = []byte("-----BEGIN CERTIFICATE-----\nLAB\n-----END CERTIFICATE-----")
	}
	policyJSON := "{}"
	if body.Policy != nil {
		b, _ := json.Marshal(body.Policy)
		policyJSON = string(b)
	}
	if err := h.Store.PutKeyVaultCertificate(vault, name, "", pem, policyJSON); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "/keyvault/" + vault + "/certificates/" + name,
		"cer": string(pem),
	})
}

func (h *Handler) getCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireDataPlaneBearer(w, r) {
		return
	}
	version, pem, _, ok, err := h.Store.GetKeyVaultCertificate(r.PathValue("vault"), r.PathValue("name"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "/keyvault/" + r.PathValue("vault") + "/certificates/" + r.PathValue("name") + "/" + version,
		"cer":     string(pem),
		"version": version,
	})
}
