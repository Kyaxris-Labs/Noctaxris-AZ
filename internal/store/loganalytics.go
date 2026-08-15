package store

import (
	"encoding/json"
	"fmt"
	"strings"
)

// QueryLogAnalyticsKQL supports `Table | take N` and `Table | where Col == 'x'` lite.
func (s *Store) QueryLogAnalyticsKQL(workspace, kql string) ([]map[string]any, error) {
	kql = strings.TrimSpace(kql)
	parts := strings.Split(kql, "|")
	if len(parts) == 0 {
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
		if strings.HasPrefix(lower, "take ") {
			var n int
			_, _ = fmt.Sscanf(op[5:], "%d", &n)
			if n > 0 && n < len(all) {
				all = all[:n]
			}
			continue
		}
		if strings.HasPrefix(lower, "where ") {
			cond := strings.TrimSpace(op[6:])
			eq := strings.SplitN(cond, "==", 2)
			if len(eq) != 2 {
				continue
			}
			col := strings.TrimSpace(eq[0])
			val := strings.Trim(strings.TrimSpace(eq[1]), "'\"")
			filtered := make([]map[string]any, 0)
			for _, row := range all {
				if fmt.Sprint(row[col]) == val {
					filtered = append(filtered, row)
				}
			}
			all = filtered
		}
	}
	return all, nil
}
