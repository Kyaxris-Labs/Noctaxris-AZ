package entra

import (
	"net/http"
	"strconv"
	"strings"
)

func applyOData(r *http.Request, items []map[string]any) (page []map[string]any, nextSkip int, hasMore bool) {
	top := 100
	skip := 0
	if v := strings.TrimSpace(r.URL.Query().Get("$top")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			top = n
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("$skiptoken")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			skip = n
		}
	}
	if skip > len(items) {
		skip = len(items)
	}
	end := skip + top
	if end > len(items) {
		end = len(items)
	}
	page = items[skip:end]
	if sel := strings.TrimSpace(r.URL.Query().Get("$select")); sel != "" {
		fields := strings.Split(sel, ",")
		trimmed := make([]map[string]any, 0, len(page))
		for _, item := range page {
			out := map[string]any{}
			for _, f := range fields {
				f = strings.TrimSpace(f)
				if v, ok := item[f]; ok {
					out[f] = v
				}
			}
			trimmed = append(trimmed, out)
		}
		page = trimmed
	}
	return page, end, end < len(items)
}

func (s *Service) writeOData(w http.ResponseWriter, r *http.Request, items []map[string]any) {
	page, nextSkip, hasMore := applyOData(r, items)
	body := map[string]any{"value": page}
	if hasMore {
		body["@odata.nextLink"] = s.base() + r.URL.Path + "?$skiptoken=" + strconv.Itoa(nextSkip)
	}
	writeJSON(w, http.StatusOK, body)
}
