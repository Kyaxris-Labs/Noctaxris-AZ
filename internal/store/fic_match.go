package store

import (
	"encoding/json"
	"regexp"
	"strings"
)

func ficExpressionValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return ""
	}
	var obj struct {
		Value string `json:"value"`
	}
	if json.Unmarshal([]byte(raw), &obj) == nil && strings.TrimSpace(obj.Value) != "" {
		return strings.TrimSpace(obj.Value)
	}
	if strings.HasPrefix(raw, "{") {
		return ""
	}
	return raw
}

func claimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// EvaluateClaimsMatchingExpression evaluates FFL-lite: claims['x'] eq/matches plus `and`.
func EvaluateClaimsMatchingExpression(expr string, claims map[string]any) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}
	for _, part := range splitAndClauses(expr) {
		if !evalFICClause(strings.TrimSpace(part), claims) {
			return false
		}
	}
	return true
}

func splitAndClauses(expr string) []string {
	var parts []string
	lower := strings.ToLower(expr)
	start := 0
	for {
		i := strings.Index(lower[start:], " and ")
		if i < 0 {
			parts = append(parts, expr[start:])
			return parts
		}
		parts = append(parts, expr[start:start+i])
		start = start + i + len(" and ")
	}
}

func evalFICClause(clause string, claims map[string]any) bool {
	key, op, want, ok := parseFICClause(clause)
	if !ok {
		return false
	}
	have := claimString(claims, key)
	switch strings.ToLower(op) {
	case "eq":
		return have == want
	case "matches":
		return globMatch(want, have)
	default:
		return false
	}
}

func parseFICClause(clause string) (key, op, want string, ok bool) {
	clause = strings.TrimSpace(clause)
	const prefix = "claims["
	if !strings.HasPrefix(strings.ToLower(clause), prefix) {
		return "", "", "", false
	}
	rest := clause[len(prefix):]
	if rest == "" || (rest[0] != '\'' && rest[0] != '"') {
		return "", "", "", false
	}
	quote := rest[0]
	rest = rest[1:]
	endKey := strings.IndexByte(rest, quote)
	if endKey < 0 {
		return "", "", "", false
	}
	key = rest[:endKey]
	rest = strings.TrimSpace(rest[endKey+1:])
	if !strings.HasPrefix(rest, "]") {
		return "", "", "", false
	}
	rest = strings.TrimSpace(rest[1:])
	opEnd := strings.IndexByte(rest, ' ')
	if opEnd < 0 {
		return "", "", "", false
	}
	op = rest[:opEnd]
	rest = strings.TrimSpace(rest[opEnd+1:])
	if rest == "" || (rest[0] != '\'' && rest[0] != '"') {
		return "", "", "", false
	}
	q := rest[0]
	rest = rest[1:]
	endVal := strings.LastIndexByte(rest, q)
	if endVal < 0 {
		return "", "", "", false
	}
	want = rest[:endVal]
	return key, op, want, key != "" && op != ""
}

func globMatch(pattern, value string) bool {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(value)
}
