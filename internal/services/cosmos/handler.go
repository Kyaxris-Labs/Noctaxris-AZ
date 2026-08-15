package cosmos

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

// Handler serves Cosmos DB NoSQL lab.
type Handler struct {
	Store *store.Store
	Auth  *authn.Authenticator
	Authz *authz.Evaluator
}

// Register mounts routes.
func (h *Handler) Register(mux *http.ServeMux) {
	base := "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DocumentDB/databaseAccounts"
	mux.HandleFunc("PUT "+base+"/{name}", h.putAccount)
	mux.HandleFunc("GET "+base+"/{name}", h.getAccount)
	mux.HandleFunc("PUT /cosmos/{account}/dbs/{db}", h.putDB)
	mux.HandleFunc("PUT /cosmos/{account}/dbs/{db}/colls/{coll}", h.putColl)
	mux.HandleFunc("PUT /cosmos/{account}/dbs/{db}/colls/{coll}/docs/{id}", h.putDoc)
	mux.HandleFunc("GET /cosmos/{account}/dbs/{db}/colls/{coll}/docs/{id}", h.getDoc)
	mux.HandleFunc("GET /cosmos/{account}/dbs/{db}/colls/{coll}/docs", h.queryDocs)
}

func (h *Handler) putAccount(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.DocumentDB/databaseAccounts/write") {
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
	key, err := h.Store.UpsertCosmosAccount(sub, rg, name, location)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.DocumentDB/databaseAccounts/" + name,
		"name": name, "type": "Microsoft.DocumentDB/databaseAccounts", "location": location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
			"documentEndpoint":  "/cosmos/" + name,
			"primaryMasterKey":  key,
		},
	})
}

func (h *Handler) getAccount(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.DocumentDB/databaseAccounts/read") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	location, key, ok, err := h.Store.GetCosmosAccount(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.DocumentDB/databaseAccounts/" + name,
		"name": name, "type": "Microsoft.DocumentDB/databaseAccounts", "location": location,
		"properties": map[string]any{"provisioningState": "Succeeded", "documentEndpoint": "/cosmos/" + name, "primaryMasterKey": key},
	})
}

func (h *Handler) putDB(w http.ResponseWriter, r *http.Request) {
	if !h.authData(w, r) {
		return
	}
	if err := h.Store.CreateCosmosDatabase(r.PathValue("account"), r.PathValue("db")); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("db")})
}

func (h *Handler) putColl(w http.ResponseWriter, r *http.Request) {
	if !h.authData(w, r) {
		return
	}
	var body struct {
		PartitionKey string `json:"partitionKey"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if err := h.Store.CreateCosmosContainer(r.PathValue("account"), r.PathValue("db"), r.PathValue("coll"), body.PartitionKey); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("coll")})
}

func (h *Handler) putDoc(w http.ResponseWriter, r *http.Request) {
	if !h.authData(w, r) {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	id := r.PathValue("id")
	pk := r.URL.Query().Get("pk")
	if pk == "" {
		pk = id
	}
	if err := h.Store.UpsertCosmosItem(r.PathValue("account"), r.PathValue("db"), r.PathValue("coll"), id, pk, string(raw)); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (h *Handler) getDoc(w http.ResponseWriter, r *http.Request) {
	if !h.authData(w, r) {
		return
	}
	id := r.PathValue("id")
	pk := r.URL.Query().Get("pk")
	if pk == "" {
		pk = id
	}
	body, ok, err := h.Store.GetCosmosItem(r.PathValue("account"), r.PathValue("db"), r.PathValue("coll"), id, pk)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "item not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func (h *Handler) queryDocs(w http.ResponseWriter, r *http.Request) {
	if !h.authData(w, r) {
		return
	}
	q := r.URL.Query().Get("query")
	id := ""
	if strings.Contains(strings.ToLower(q), "id") {
		// lab: extract quoted id
		for _, p := range strings.Split(q, "'") {
			if len(p) > 0 && !strings.Contains(strings.ToLower(p), "select") && !strings.Contains(p, "=") {
				id = p
				break
			}
		}
	}
	if id == "" {
		id = r.URL.Query().Get("id")
	}
	docs, err := h.Store.QueryCosmosItemsByID(r.PathValue("account"), r.PathValue("db"), r.PathValue("coll"), id)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	items := make([]json.RawMessage, 0, len(docs))
	for _, d := range docs {
		items = append(items, json.RawMessage(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"Documents": items})
}

func (h *Handler) authData(w http.ResponseWriter, r *http.Request) bool {
	account := r.PathValue("account")
	_, _, _, key, ok, err := h.Store.GetCosmosAccountByName(account)
	if err != nil || !ok {
		azerrors.NotFound(w, "account not found")
		return false
	}
	if hdr := r.Header.Get("x-ms-cosmos-account-key"); hdr != "" {
		if hdr == key {
			return true
		}
		azerrors.Unauthenticated(w, "")
		return false
	}
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
