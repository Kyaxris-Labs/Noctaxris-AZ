package keyvault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
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
	policyJSON := "{}"
	if body.Policy != nil {
		b, _ := json.Marshal(body.Policy)
		policyJSON = string(b)
	}
	exportable := certificatePolicyExportable(body.Policy)
	pemBytes := []byte(body.Value)
	if exportable {
		certPEM, keyPEM, err := issueExportableCertificate(body.Value)
		if err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		pemBytes = certPEM
		if _, err := h.Store.PutSecret(vault, name, string(keyPEM)); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
	} else if len(pemBytes) == 0 {
		pemBytes = []byte("-----BEGIN CERTIFICATE-----\nLAB\n-----END CERTIFICATE-----")
	}
	if err := h.Store.PutKeyVaultCertificate(vault, name, "", pemBytes, policyJSON); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":  "/keyvault/" + vault + "/certificates/" + name,
		"cer": string(pemBytes),
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

func (h *Handler) certificateSecretBlocked(vault, name string) (bool, error) {
	_, _, policyJSON, ok, err := h.Store.GetKeyVaultCertificate(vault, name)
	if err != nil || !ok {
		return false, err
	}
	return !certificatePolicyExportableJSON(policyJSON), nil
}

func certificatePolicyExportableJSON(policyJSON string) bool {
	var m map[string]any
	if json.Unmarshal([]byte(policyJSON), &m) != nil {
		return false
	}
	return certificatePolicyExportable(m)
}

func certificatePolicyExportable(policy map[string]any) bool {
	if policy == nil {
		return false
	}
	if b, ok := policy["exportable"].(bool); ok && b {
		return true
	}
	for _, nest := range []string{"key_props", "keyProperties", "keyProps"} {
		inner, ok := policy[nest].(map[string]any)
		if !ok {
			continue
		}
		if b, ok := inner["exportable"].(bool); ok && b {
			return true
		}
	}
	return false
}

func issueExportableCertificate(raw string) (certPEM, keyPEM []byte, err error) {
	key, err := parseOrGenerateRSAKey(raw)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "lab"},
		NotBefore:    time.Now().UTC().Add(-time.Hour),
		NotAfter:     time.Now().UTC().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return certPEM, keyPEM, nil
}

func parseOrGenerateRSAKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block != nil {
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if pk, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if key, ok := pk.(*rsa.PrivateKey); ok {
				return key, nil
			}
		}
	}
	return rsa.GenerateKey(rand.Reader, 2048)
}
