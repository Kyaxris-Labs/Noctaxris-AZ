package server

import "strings"

// canonicalizeARMPath maps the Resource Groups REST segment `resourcegroups`
// (see https://learn.microsoft.com/en-us/rest/api/resources/resource-groups/create-or-update)
// to `resourceGroups`, which is the casing used in Azure resource IDs and in
// nested provider routes. Go's ServeMux is case-sensitive; ARM is not.
func canonicalizeARMPath(path string) string {
	if path == "" || !strings.Contains(strings.ToLower(path), "resourcegroups") {
		return path
	}
	parts := strings.Split(path, "/")
	changed := false
	for i, p := range parts {
		if strings.EqualFold(p, "resourcegroups") && p != "resourceGroups" {
			parts[i] = "resourceGroups"
			changed = true
		}
	}
	if !changed {
		return path
	}
	return strings.Join(parts, "/")
}
