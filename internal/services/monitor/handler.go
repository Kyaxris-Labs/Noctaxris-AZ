package monitor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

// Handler serves Activity Log list and metrics theatre.
type Handler struct {
	Store *store.Store
	Authz *authz.Evaluator
}

type principalFunc func(*http.Request) (authn.Principal, bool)

// Mount registers Monitor / Activity Log routes.
func (h *Handler) Mount(mux *http.ServeMux, principalFrom principalFunc) {
	mux.HandleFunc("GET /subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values",
		h.wrap(principalFrom, h.listActivity))
	mux.HandleFunc("POST /subscriptions/{sub}/providers/Microsoft.Insights/metrics",
		h.wrap(principalFrom, h.writeMetric))
	mux.HandleFunc("GET /subscriptions/{sub}/providers/Microsoft.Insights/metrics",
		h.wrap(principalFrom, h.listMetrics))
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p authn.Principal)

func (h *Handler) wrap(principalFrom principalFunc, fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFrom(r)
		if !ok {
			azerrors.Unauthenticated(w, "")
			return
		}
		fn(w, r, p)
	}
}

func (h *Handler) require(p authn.Principal, action, scope string) error {
	ok, err := h.Authz.Evaluate(p.ID, p.IsRoot, action, scope)
	if err != nil {
		return err
	}
	if !ok {
		return errDenied
	}
	return nil
}

var errDenied = fmt.Errorf("permission denied")

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAuthz(w http.ResponseWriter, err error) {
	if err == errDenied {
		azerrors.Forbidden(w, "")
		return
	}
	azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
}

func (h *Handler) listActivity(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub := r.PathValue("sub")
	scope := "/subscriptions/" + sub
	if err := h.require(p, "Microsoft.Insights/eventtypes/values/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("$top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := h.Store.ListActivityLog(limit)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]any, 0, len(rows))
	for _, row := range rows {
		value = append(value, map[string]any{
			"eventTimestamp":   row["timestamp"],
			"caller":           row["caller"],
			"operationName":    map[string]string{"value": row["operation"], "localizedValue": row["operation"]},
			"resourceId":       row["resourceId"],
			"status":           map[string]string{"value": row["status"], "localizedValue": row["status"]},
			"description":      row["message"],
			"subscriptionId":   sub,
			"eventDataId":      row["timestamp"] + "|" + row["operation"],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (h *Handler) writeMetric(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub := r.PathValue("sub")
	scope := "/subscriptions/" + sub
	if err := h.require(p, "Microsoft.Insights/metrics/write", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	var body struct {
		Name       string  `json:"name"`
		Value      float64 `json:"value"`
		ResourceID string  `json:"resourceId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		azerrors.BadRequest(w, "invalid JSON body")
		return
	}
	if body.Name == "" {
		azerrors.BadRequest(w, "name is required")
		return
	}
	if err := h.Store.WriteMetric(body.Name, body.Value, body.ResourceID); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":       body.Name,
		"value":      body.Value,
		"resourceId": body.ResourceID,
	})
}

func (h *Handler) listMetrics(w http.ResponseWriter, r *http.Request, p authn.Principal) {
	sub := r.PathValue("sub")
	scope := "/subscriptions/" + sub
	if err := h.require(p, "Microsoft.Insights/metrics/read", scope); err != nil {
		writeAuthz(w, err)
		return
	}
	name := r.URL.Query().Get("metricnames")
	if name == "" {
		name = r.URL.Query().Get("name")
	}
	limit := 50
	if v := r.URL.Query().Get("$top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := h.Store.ListMetrics(name, limit)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]any, 0, len(rows))
	for _, row := range rows {
		value = append(value, map[string]any{
			"name":       map[string]any{"value": row["name"], "localizedValue": row["name"]},
			"timeseries": []any{map[string]any{"data": []any{map[string]any{"average": row["value"], "timeStamp": row["timestamp"]}}}},
			"resourceId": row["resourceId"],
			"unit":       "Count",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value, "subscriptionId": sub})
}

// AppendActivity is an optional helper other packages may call to record ARM mutations.
func AppendActivity(st *store.Store, caller, operation, resourceID, status, message string) error {
	if st == nil {
		return nil
	}
	return st.AppendActivityLog(caller, operation, resourceID, status, message)
}
