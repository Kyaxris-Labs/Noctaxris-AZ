package storage

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

// Handler serves Storage ARM and lab data-plane routes.
type Handler struct {
	Store      *store.Store
	Auth       *authn.Authenticator
	Authz      *authz.Evaluator
	ListenAddr string
}

// Register mounts Storage routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}", h.putAccount)
	mux.HandleFunc("GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}", h.getAccount)

	mux.HandleFunc("PUT /blob/{account}/{container}", h.putContainer)
	mux.HandleFunc("PUT /blob/{account}/{container}/{blob}", h.putBlob)
	mux.HandleFunc("GET /blob/{account}/{container}/{blob}", h.getBlob)

	mux.HandleFunc("PUT /queue/{account}/{queue}", h.putQueue)
	mux.HandleFunc("POST /queue/{account}/{queue}", h.postQueueMessage)
	mux.HandleFunc("GET /queue/{account}/{queue}", h.getQueueMessage)
}

func (h *Handler) putAccount(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.Storage/storageAccounts/write", armScope(r)) {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	name := r.PathValue("name")
	location := "eastus"
	var body struct {
		Location   string         `json:"location"`
		Properties map[string]any `json:"properties"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if body.Location != "" {
		location = body.Location
	}
	key, err := h.Store.UpsertStorageAccount(sub, rg, name, location, h.ListenAddr)
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	_ = key
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.Storage/storageAccounts/" + name
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"name":     name,
		"type":     "Microsoft.Storage/storageAccounts",
		"location": location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
			"primaryEndpoints": map[string]string{
				"blob":  "/blob/" + name,
				"queue": "/queue/" + name,
			},
		},
	})
}

func (h *Handler) getAccount(w http.ResponseWriter, r *http.Request) {
	if !h.requireBearerARM(w, r, "Microsoft.Storage/storageAccounts/read", armScope(r)) {
		return
	}
	sub := r.PathValue("sub")
	rg := r.PathValue("rg")
	name := r.PathValue("name")
	location, ok, err := h.Store.GetStorageAccount(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "storage account not found")
		return
	}
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.Storage/storageAccounts/" + name
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"name":     name,
		"type":     "Microsoft.Storage/storageAccounts",
		"location": location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
		},
	})
}

func (h *Handler) putContainer(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	container := r.PathValue("container")
	if !h.authorizeDataPlane(w, r, account) {
		return
	}
	if err := h.Store.CreateContainer(account, container); err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) putBlob(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	container := r.PathValue("container")
	blob := r.PathValue("blob")
	if !h.authorizeDataPlane(w, r, account) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		azerrors.StorageError(w, http.StatusBadRequest, "InvalidInput", err.Error())
		return
	}
	ct := r.Header.Get("Content-Type")
	if err := h.Store.PutBlob(account, container, blob, body, ct); err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.Header().Set("x-ms-request-server-encrypted", "false")
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) getBlob(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	container := r.PathValue("container")
	blob := r.PathValue("blob")
	if !h.authorizeDataPlane(w, r, account) {
		return
	}
	content, ct, ok, err := h.Store.GetBlob(account, container, blob)
	if err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.StorageError(w, http.StatusNotFound, "BlobNotFound", "The specified blob does not exist.")
		return
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (h *Handler) putQueue(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	queue := r.PathValue("queue")
	if !h.authorizeDataPlane(w, r, account) {
		return
	}
	if err := h.Store.CreateQueue(account, queue); err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) postQueueMessage(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	queue := r.PathValue("queue")
	if !h.authorizeDataPlane(w, r, account) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.StorageError(w, http.StatusBadRequest, "InvalidInput", err.Error())
		return
	}
	msg := strings.TrimSpace(string(body))
	var envelope struct {
		MessageText string `json:"MessageText"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.MessageText != "" {
		msg = envelope.MessageText
	}
	if err := h.Store.Enqueue(account, queue, msg); err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"messageId": "1"})
}

func (h *Handler) getQueueMessage(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	queue := r.PathValue("queue")
	if !h.authorizeDataPlane(w, r, account) {
		return
	}
	body, ok, err := h.Store.Dequeue(account, queue)
	if err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"MessageText": body})
}

func (h *Handler) authorizeDataPlane(w http.ResponseWriter, r *http.Request, account string) bool {
	if authn.HasSAS(r) {
		return true
	}
	if acct, sig, ok := authn.ParseSharedKeyAuthorization(r.Header.Get("Authorization")); ok {
		if acct != account {
			azerrors.StorageError(w, http.StatusForbidden, "AuthenticationFailed", "account name mismatch")
			return false
		}
		key, found, err := h.Store.GetStorageAccountKey(account)
		if err != nil {
			azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return false
		}
		if !found {
			azerrors.StorageError(w, http.StatusNotFound, "AccountNotFound", "storage account not found")
			return false
		}
		if !authn.VerifyStorageSharedKey(key, authn.StorageStringToSign(r), sig) {
			azerrors.StorageError(w, http.StatusForbidden, "AuthenticationFailed", "SharedKey signature invalid")
			return false
		}
		return true
	}
	if h.Auth != nil {
		p, err := h.Auth.AuthenticateRequest(r)
		if err == nil && p.IsRoot {
			return true
		}
	}
	azerrors.StorageError(w, http.StatusUnauthorized, "AuthenticationFailed", "SharedKey, SAS, or root Bearer required")
	return false
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
