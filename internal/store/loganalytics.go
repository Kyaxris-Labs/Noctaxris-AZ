package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	LogTableAPIManagementGatewayLogs          = "ApiManagementGatewayLogs"
	LogTableAADManagedIdentitySignInLogs      = "AADManagedIdentitySignInLogs"
	LogTableAADServicePrincipalSignInLogs     = "AADServicePrincipalSignInLogs"
	LogTableAzureActivity                     = "AzureActivity"
	LogTableContainerAppSystemLogs            = "ContainerAppSystemLogs"
	LogTableDataPlaneRequests                 = "DataPlaneRequests"
	LogTableContainerRegistryRepositoryEvents = "ContainerRegistryRepositoryEvents"
	DefaultLogAnalyticsWorkspace              = "default"
)

// NamedLogAnalyticsTables are the lab inject / live-audit table names.
var NamedLogAnalyticsTables = []string{
	LogTableAPIManagementGatewayLogs,
	LogTableAADManagedIdentitySignInLogs,
	LogTableAADServicePrincipalSignInLogs,
	LogTableAzureActivity,
	LogTableContainerAppSystemLogs,
	LogTableDataPlaneRequests,
	LogTableContainerRegistryRepositoryEvents,
}

// IsNamedLogAnalyticsTable reports whether table is in the inject allowlist.
func IsNamedLogAnalyticsTable(table string) bool {
	switch strings.TrimSpace(table) {
	case LogTableAPIManagementGatewayLogs,
		LogTableAADManagedIdentitySignInLogs,
		LogTableAADServicePrincipalSignInLogs,
		LogTableAzureActivity,
		LogTableContainerAppSystemLogs,
		LogTableDataPlaneRequests,
		LogTableContainerRegistryRepositoryEvents:
		return true
	default:
		return false
	}
}

// QueryLogAnalyticsKQL supports Table | take N, where Col == 'x', TimeGenerated
// range, and project of stored columns. Not full Azure Monitor KQL.
func (s *Store) QueryLogAnalyticsKQL(workspace, kql string) ([]map[string]any, error) {
	kql = strings.TrimSpace(kql)
	parts := strings.Split(kql, "|")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return nil, fmt.Errorf("empty kql")
	}
	table := strings.TrimSpace(parts[0])
	rows, err := s.db.Query(`
SELECT row_json FROM log_analytics_rows WHERE workspace = ? AND table_name = ? ORDER BY id`, workspace, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all []map[string]any
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			m = map[string]any{"raw": raw}
		}
		all = append(all, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := 1; i < len(parts); i++ {
		op := strings.TrimSpace(parts[i])
		lower := strings.ToLower(op)
		switch {
		case strings.HasPrefix(lower, "take "):
			var n int
			_, _ = fmt.Sscanf(strings.TrimSpace(op[5:]), "%d", &n)
			if n > 0 && n < len(all) {
				all = all[:n]
			}
		case strings.HasPrefix(lower, "where "):
			all = applyKQLWhere(all, strings.TrimSpace(op[6:]))
		case strings.HasPrefix(lower, "project "):
			cols := splitKQLProject(op[8:])
			all = applyKQLProject(all, cols)
		}
	}
	return all, nil
}

func splitKQLProject(raw string) []string {
	var cols []string
	for _, p := range strings.Split(raw, ",") {
		c := strings.TrimSpace(p)
		if c != "" {
			cols = append(cols, c)
		}
	}
	return cols
}

func applyKQLProject(rows []map[string]any, cols []string) []map[string]any {
	if len(cols) == 0 {
		return rows
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		next := make(map[string]any, len(cols))
		for _, c := range cols {
			if v, ok := row[c]; ok {
				next[c] = v
			}
		}
		out = append(out, next)
	}
	return out
}

func applyKQLWhere(rows []map[string]any, cond string) []map[string]any {
	col, op, rawVal, ok := parseKQLCompare(cond)
	if !ok {
		return rows
	}
	filtered := make([]map[string]any, 0, len(rows))
	if strings.EqualFold(col, "TimeGenerated") {
		want, perr := parseKQLTime(rawVal)
		if perr != nil {
			return rows
		}
		for _, row := range rows {
			got, gerr := parseRowTime(row[col])
			if gerr != nil {
				continue
			}
			if compareTime(got, op, want) {
				filtered = append(filtered, row)
			}
		}
		return filtered
	}
	if op != "==" {
		return rows
	}
	want := strings.Trim(rawVal, "'\"")
	for _, row := range rows {
		if fmt.Sprint(row[col]) == want {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func parseKQLCompare(cond string) (col, op, val string, ok bool) {
	cond = strings.TrimSpace(cond)
	for _, cand := range []string{">=", "<=", "==", ">", "<"} {
		i := strings.Index(cond, cand)
		if i <= 0 {
			continue
		}
		col = strings.TrimSpace(cond[:i])
		val = strings.TrimSpace(cond[i+len(cand):])
		if col == "" || val == "" {
			return "", "", "", false
		}
		return col, cand, val, true
	}
	return "", "", "", false
}

func parseKQLTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(raw), "datetime(") && strings.HasSuffix(raw, ")") {
		raw = strings.TrimSpace(raw[len("datetime(") : len(raw)-1])
	}
	raw = strings.Trim(raw, `"'`)
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), nil
	}
	return time.Parse(time.RFC3339, raw)
}

func parseRowTime(v any) (time.Time, error) {
	s := strings.TrimSpace(fmt.Sprint(v))
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	return time.Parse(time.RFC3339, s)
}

func compareTime(got time.Time, op string, want time.Time) bool {
	switch op {
	case ">=":
		return !got.Before(want)
	case "<=":
		return !got.After(want)
	case ">":
		return got.After(want)
	case "<":
		return got.Before(want)
	case "==":
		return got.Equal(want)
	default:
		return false
	}
}
