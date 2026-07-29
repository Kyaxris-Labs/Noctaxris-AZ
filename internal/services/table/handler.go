package table

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

// Handler serves Table Storage lab data-plane routes under /table/{account}/...
type Handler struct {
	Store *store.Store
	Auth  *authn.Authenticator
}

// Register mounts Table routes on mux.
//
// Azure Tables REST lite (path-style on the shared HTTP port):
//
//	PUT/DELETE  /table/{account}/{table}
//	GET         /table/{account}                         list tables
//	GET         /table/{account}/{table}?$filter&$top    query entities
//	POST        /table/{account}/{table}                 insert entity
//	GET/PUT/MERGE/DELETE /table/{account}/{table}/{pk}/{rk}
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /table/{account}", h.listTables)
	mux.HandleFunc("PUT /table/{account}/{table}", h.putTable)
	mux.HandleFunc("GET /table/{account}/{table}", h.getTableOrQuery)
	mux.HandleFunc("DELETE /table/{account}/{table}", h.deleteTable)
	mux.HandleFunc("POST /table/{account}/{table}", h.insertEntity)
	mux.HandleFunc("PUT /table/{account}/{table}/{pk}/{rk}", h.putEntity)
	mux.HandleFunc("MERGE /table/{account}/{table}/{pk}/{rk}", h.mergeEntity)
	mux.HandleFunc("GET /table/{account}/{table}/{pk}/{rk}", h.getEntity)
	mux.HandleFunc("DELETE /table/{account}/{table}/{pk}/{rk}", h.deleteEntity)
}

func (h *Handler) listTables(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	if !h.authorize(w, r, account) {
		return
	}
	names, err := h.Store.ListTables(account)
	if err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	value := make([]map[string]string, 0, len(names))
	for _, n := range names {
		value = append(value, map[string]string{"TableName": n})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (h *Handler) putTable(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	tableName := r.PathValue("table")
	if !h.authorize(w, r, account) {
		return
	}
	if err := h.Store.CreateTable(account, tableName); err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"TableName": tableName})
}

func (h *Handler) deleteTable(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	tableName := r.PathValue("table")
	if !h.authorize(w, r, account) {
		return
	}
	if err := h.Store.DeleteTable(account, tableName); err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getTableOrQuery(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	tableName := r.PathValue("table")
	if !h.authorize(w, r, account) {
		return
	}
	filter := r.URL.Query().Get("$filter")
	top := 0
	if t := strings.TrimSpace(r.URL.Query().Get("$top")); t != "" {
		n, err := strconv.Atoi(t)
		if err != nil || n < 0 {
			azerrors.StorageError(w, http.StatusBadRequest, "InvalidInput", "$top must be a non-negative integer")
			return
		}
		top = n
	}
	pk, rk, propEq := parseFilterLite(filter)
	ents, err := h.Store.QueryEntities(account, tableName, pk, rk, propEq, top)
	if err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(ents))
	for _, e := range ents {
		row := map[string]any{
			"PartitionKey": e.PartitionKey,
			"RowKey":       e.RowKey,
			"odata.etag":   e.ETag,
		}
		for k, v := range e.Properties {
			row[k] = v
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": out})
}

func (h *Handler) insertEntity(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	tableName := r.PathValue("table")
	if !h.authorize(w, r, account) {
		return
	}
	props, pk, rk, err := readEntityBody(r)
	if err != nil {
		azerrors.StorageError(w, http.StatusBadRequest, "InvalidInput", err.Error())
		return
	}
	etag, created, err := h.Store.InsertEntity(account, tableName, pk, rk, props)
	if err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !created {
		azerrors.StorageError(w, http.StatusConflict, "EntityAlreadyExists", "entity already exists")
		return
	}
	w.Header().Set("ETag", etag)
	row := map[string]any{"PartitionKey": pk, "RowKey": rk, "odata.etag": etag}
	for k, v := range props {
		row[k] = v
	}
	writeJSON(w, http.StatusCreated, row)
}

func (h *Handler) putEntity(w http.ResponseWriter, r *http.Request) {
	h.writeEntity(w, r, false)
}

func (h *Handler) mergeEntity(w http.ResponseWriter, r *http.Request) {
	h.writeEntity(w, r, true)
}

func (h *Handler) writeEntity(w http.ResponseWriter, r *http.Request, merge bool) {
	account := r.PathValue("account")
	tableName := r.PathValue("table")
	pk := r.PathValue("pk")
	rk := r.PathValue("rk")
	if !h.authorize(w, r, account) {
		return
	}
	props, _, _, err := readEntityBody(r)
	if err != nil {
		azerrors.StorageError(w, http.StatusBadRequest, "InvalidInput", err.Error())
		return
	}
	etag, err := h.Store.UpsertEntity(account, tableName, pk, rk, props, merge)
	if err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getEntity(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	tableName := r.PathValue("table")
	pk := r.PathValue("pk")
	rk := r.PathValue("rk")
	if !h.authorize(w, r, account) {
		return
	}
	ent, ok, err := h.Store.GetEntity(account, tableName, pk, rk)
	if err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.StorageError(w, http.StatusNotFound, "ResourceNotFound", "entity not found")
		return
	}
	w.Header().Set("ETag", ent.ETag)
	row := map[string]any{
		"PartitionKey": ent.PartitionKey,
		"RowKey":       ent.RowKey,
		"odata.etag":   ent.ETag,
	}
	for k, v := range ent.Properties {
		row[k] = v
	}
	writeJSON(w, http.StatusOK, row)
}

func (h *Handler) deleteEntity(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	tableName := r.PathValue("table")
	pk := r.PathValue("pk")
	rk := r.PathValue("rk")
	if !h.authorize(w, r, account) {
		return
	}
	ok, err := h.Store.DeleteEntity(account, tableName, pk, rk)
	if err != nil {
		azerrors.StorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.StorageError(w, http.StatusNotFound, "ResourceNotFound", "entity not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, account string) bool {
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

func readEntityBody(r *http.Request) (props map[string]any, pk, rk string, err error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, "", "", err
	}
	props = map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &props); err != nil {
			return nil, "", "", err
		}
	}
	pk, _ = props["PartitionKey"].(string)
	rk, _ = props["RowKey"].(string)
	if pk == "" {
		pk = r.PathValue("pk")
	}
	if rk == "" {
		rk = r.PathValue("rk")
	}
	if pk == "" || rk == "" {
		return nil, "", "", errMissingKeys
	}
	delete(props, "PartitionKey")
	delete(props, "RowKey")
	return props, pk, rk, nil
}

var errMissingKeys = errString("PartitionKey and RowKey are required")

type errString string

func (e errString) Error() string { return string(e) }

var eqFilter = regexp.MustCompile(`(?i)(\w+)\s+eq\s+'([^']*)'`)

func parseFilterLite(filter string) (pk, rk string, propEq map[string]string) {
	propEq = map[string]string{}
	if strings.TrimSpace(filter) == "" {
		return "", "", propEq
	}
	for _, m := range eqFilter.FindAllStringSubmatch(filter, -1) {
		if len(m) != 3 {
			continue
		}
		key, val := m[1], m[2]
		switch strings.ToLower(key) {
		case "partitionkey":
			pk = val
		case "rowkey":
			rk = val
		default:
			propEq[key] = val
		}
	}
	return pk, rk, propEq
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
