package cosmos

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/azauth"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const (
	actionItemsRead  = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read"
	actionItemsWrite = "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/write"
	actionListKeys   = "Microsoft.DocumentDB/databaseAccounts/listKeys/action"
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
	mux.HandleFunc("POST "+base+"/{name}/listKeys", h.listKeys)
	mux.HandleFunc("PUT /cosmos/{account}/dbs/{db}", h.putDB)
	mux.HandleFunc("PUT /cosmos/{account}/dbs/{db}/colls/{coll}", h.putColl)
	mux.HandleFunc("PUT /cosmos/{account}/dbs/{db}/colls/{coll}/docs/{id}", h.putDoc)
	mux.HandleFunc("GET /cosmos/{account}/dbs/{db}/colls/{coll}/docs/{id}", h.getDoc)
	mux.HandleFunc("GET /cosmos/{account}/dbs/{db}/colls/{coll}/docs", h.queryDocs)
	mux.HandleFunc("GET /cosmos/{account}/dbs/{db}/colls/{coll}/changefeed", h.changeFeed)
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
	if _, err := h.Store.UpsertCosmosAccount(sub, rg, name, location); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	// Master keys stay in store and are returned only from listKeys.
	writeJSON(w, http.StatusOK, map[string]any{
		"id":   "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.DocumentDB/databaseAccounts/" + name,
		"name": name, "type": "Microsoft.DocumentDB/databaseAccounts", "location": location,
		"properties": map[string]any{
			"provisioningState": "Succeeded",
			"documentEndpoint":  "/cosmos/" + name,
		},
	})
}

func (h *Handler) getAccount(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.DocumentDB/databaseAccounts/read") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	location, _, ok, err := h.Store.GetCosmosAccount(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":   "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.DocumentDB/databaseAccounts/" + name,
		"name": name, "type": "Microsoft.DocumentDB/databaseAccounts", "location": location,
		"properties": map[string]any{"provisioningState": "Succeeded", "documentEndpoint": "/cosmos/" + name},
	})
}

func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, actionListKeys) {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	_, key, ok, err := h.Store.GetCosmosAccount(sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"primaryMasterKey":           key,
		"secondaryMasterKey":         key,
		"primaryReadonlyMasterKey":   key,
		"secondaryReadonlyMasterKey": key,
	})
}

func (h *Handler) putDB(w http.ResponseWriter, r *http.Request) {
	if !h.authData(w, r, actionItemsWrite) {
		return
	}
	if err := h.Store.CreateCosmosDatabase(r.PathValue("account"), r.PathValue("db")); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("db")})
}

func (h *Handler) putColl(w http.ResponseWriter, r *http.Request) {
	if !h.authData(w, r, actionItemsWrite) {
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
	if !h.authData(w, r, actionItemsWrite) {
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
	if !h.authData(w, r, actionItemsRead) {
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
	if !h.authData(w, r, actionItemsRead) {
		return
	}
	q := r.URL.Query().Get("query")
	id := ""
	if strings.Contains(strings.ToLower(q), "id") {
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

func (h *Handler) changeFeed(w http.ResponseWriter, r *http.Request) {
	if !h.authData(w, r, actionItemsRead) {
		return
	}
	docs, err := h.Store.ListCosmosItems(r.PathValue("account"), r.PathValue("db"), r.PathValue("coll"))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	items := make([]json.RawMessage, 0, len(docs))
	for _, d := range docs {
		if json.Valid([]byte(d)) {
			items = append(items, json.RawMessage(d))
			continue
		}
		b, _ := json.Marshal(map[string]any{"raw": d})
		items = append(items, b)
	}
	writeJSON(w, http.StatusOK, map[string]any{"Documents": items})
}

func (h *Handler) authData(w http.ResponseWriter, r *http.Request, action string) bool {
	account := r.PathValue("account")
	sub, rg, _, key, exists, err := h.Store.GetCosmosAccountByName(account)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return false
	}
	if hdr := strings.TrimSpace(r.Header.Get("x-ms-cosmos-account-key")); hdr != "" {
		// Account-key path: never reveal whether the account name exists.
		if !exists || hdr != key {
			azerrors.Unauthenticated(w, "")
			return false
		}
		return true
	}
	scope := "/subscriptions/" + config.DefaultSubscriptionID
	if exists {
		scope = "/subscriptions/" + sub + "/resourceGroups/" + rg +
			"/providers/Microsoft.DocumentDB/databaseAccounts/" + account
	}
	if _, ok := azauth.RequireDataPlaneBearer(w, r, h.Auth, h.Authz, authn.Principal.AllowsCosmos, action, scope); !ok {
		return false
	}
	if !exists {
		azerrors.NotFound(w, "account not found")
		return false
	}
	return true
}

func (h *Handler) require(w http.ResponseWriter, r *http.Request, action string) bool {
	scope := "/subscriptions/" + r.PathValue("sub") + "/resourceGroups/" + r.PathValue("rg")
	_, ok := azauth.RequireARMBearer(w, r, h.Auth, h.Authz, action, scope)
	return ok
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
