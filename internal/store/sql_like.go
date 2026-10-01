package store

import "strings"

// likeEscape escapes SQLite LIKE metacharacters so a literal prefix match is safe.
func likeEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// likePrefixChildren returns a LIKE pattern for resource ids under prefix (prefix + "/%").
func likePrefixChildren(prefix string) string {
	return likeEscape(prefix) + `/%`
}
