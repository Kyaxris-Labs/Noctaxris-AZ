package authz

import (
	"strings"
)

// Assignment is an Azure RBAC role assignment.
type Assignment struct {
	ID               string
	Scope            string
	RoleDefinitionID string
	PrincipalID      string
	PrincipalType    string
}

// AssignmentStore lists role assignments that apply to a scope.
type AssignmentStore interface {
	ListRoleAssignmentsForScope(scope string) ([]Assignment, error)
}

// Evaluator checks Azure RBAC grants. Root bypasses. Deny by default.
type Evaluator struct {
	Assignments AssignmentStore
}

// Evaluate returns true when principal may perform action on scope.
func (e *Evaluator) Evaluate(principalID string, isRoot bool, action, scope string) (bool, error) {
	if isRoot {
		return true, nil
	}
	if e == nil || e.Assignments == nil || principalID == "" || action == "" || scope == "" {
		return false, nil
	}
	for _, sc := range scopeChain(scope) {
		as, err := e.Assignments.ListRoleAssignmentsForScope(sc)
		if err != nil {
			return false, err
		}
		for _, a := range as {
			if a.PrincipalID != principalID {
				continue
			}
			if roleGrants(a.RoleDefinitionID, action) {
				return true, nil
			}
		}
	}
	return false, nil
}

func scopeChain(scope string) []string {
	out := []string{scope}
	// Parent scopes: trim trailing segments under /subscriptions/...
	parts := strings.Split(strings.Trim(scope, "/"), "/")
	for i := len(parts) - 1; i >= 1; i-- {
		parent := "/" + strings.Join(parts[:i], "/")
		if parent != scope {
			out = append(out, parent)
		}
	}
	return out
}

func roleGrants(roleDefID, action string) bool {
	role := strings.ToLower(roleDefID)
	act := strings.ToLower(action)
	switch {
	case strings.Contains(role, "owner") || strings.HasSuffix(role, "/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"):
		return true
	case strings.Contains(role, "contributor") || strings.HasSuffix(role, "/b24988ac-6180-42a0-ab88-20f7382dd24c"):
		return !strings.Contains(act, "authorization/roleassignments")
	case strings.Contains(role, "reader") || strings.HasSuffix(role, "/acdd72a7-3385-48ef-bd42-f606fba81ae7"):
		return strings.HasSuffix(act, "/read") || strings.Contains(act, "/read")
	default:
		return false
	}
}

// Built-in role definition IDs (Azure well-known).
const (
	RoleOwner        = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	RoleContributor  = "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
	RoleReader       = "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
)
