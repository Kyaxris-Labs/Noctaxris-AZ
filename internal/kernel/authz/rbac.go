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

// GroupMembershipStore expands Entra group members for ARM evaluation.
// Store already implements this; Graph handlers are not required.
type GroupMembershipStore interface {
	ListGroupMembers(groupID string) (ids []string, types []string, err error)
}

// Evaluator checks Azure RBAC grants. Root bypasses. Deny by default.
type Evaluator struct {
	Assignments AssignmentStore
}

const groupExpandMaxDepth = 8

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
			ok, err := e.principalMatches(a, principalID)
			if err != nil {
				return false, err
			}
			if !ok {
				continue
			}
			if roleGrants(a.RoleDefinitionID, action) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (e *Evaluator) principalMatches(a Assignment, principalID string) (bool, error) {
	if a.PrincipalID == principalID {
		return true, nil
	}
	pt := strings.ToLower(strings.TrimSpace(a.PrincipalType))
	if pt != "" && pt != "group" {
		return false, nil
	}
	gm, ok := e.membership()
	if !ok {
		return false, nil
	}
	return groupContains(gm, a.PrincipalID, principalID, 0, map[string]struct{}{})
}

func (e *Evaluator) membership() (GroupMembershipStore, bool) {
	if e == nil || e.Assignments == nil {
		return nil, false
	}
	gm, ok := e.Assignments.(GroupMembershipStore)
	return gm, ok
}

func groupContains(gm GroupMembershipStore, groupID, principalID string, depth int, seen map[string]struct{}) (bool, error) {
	if gm == nil || groupID == "" || principalID == "" || depth >= groupExpandMaxDepth {
		return false, nil
	}
	if _, ok := seen[groupID]; ok {
		return false, nil
	}
	seen[groupID] = struct{}{}
	ids, types, err := gm.ListGroupMembers(groupID)
	if err != nil {
		return false, err
	}
	for i, id := range ids {
		if id == principalID {
			return true, nil
		}
		typ := ""
		if i < len(types) {
			typ = strings.ToLower(strings.TrimSpace(types[i]))
		}
		if typ == "group" {
			ok, err := groupContains(gm, id, principalID, depth+1, seen)
			if err != nil || ok {
				return ok, err
			}
		}
	}
	return false, nil
}

func scopeChain(scope string) []string {
	out := []string{scope}
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
	role := strings.ToLower(strings.TrimSpace(roleDefID))
	act := strings.ToLower(strings.TrimSpace(action))
	if role == "" || act == "" {
		return false
	}
	switch {
	case roleHasGUID(role, guidOwner) || strings.Contains(role, "owner"):
		return true
	case roleHasGUID(role, guidContributor) || strings.Contains(role, "contributor"):
		return !strings.Contains(act, "authorization/roleassignments")
	case roleHasGUID(role, guidLogAnalyticsDataReader):
		return isWorkspaceQueryAction(act) || act == "microsoft.operationalinsights/workspaces/read"
	case roleHasGUID(role, guidAcrPull):
		return isAcrPullAction(act)
	case roleHasGUID(role, guidEventHubsDataOwner):
		return strings.Contains(act, "eventhub")
	case roleHasGUID(role, guidEventHubsDataReceiver):
		return isEventHubsReceiveAction(act)
	case isReaderLikeRole(role):
		return isReadLikeAction(act)
	default:
		return false
	}
}

func isReaderLikeRole(role string) bool {
	if roleHasGUID(role, guidReader) ||
		roleHasGUID(role, guidLogAnalyticsReader) ||
		roleHasGUID(role, guidLogAnalyticsReaderAlias) ||
		roleHasGUID(role, guidMonitoringReader) {
		return true
	}
	if role == "reader" || strings.HasSuffix(role, "/reader") {
		return true
	}
	return strings.Contains(role, "log analytics reader") || strings.Contains(role, "monitoring reader")
}

func isReadLikeAction(act string) bool {
	if strings.HasSuffix(act, "/read") || strings.Contains(act, "/read/") || strings.Contains(act, "/read") {
		return true
	}
	return isWorkspaceQueryAction(act) || isResourceGraphRead(act)
}

func isWorkspaceQueryAction(act string) bool {
	return strings.Contains(act, "workspaces/query") ||
		strings.Contains(act, "workspaces/analytics/query") ||
		strings.Contains(act, "workspaces/search/action")
}

func isResourceGraphRead(act string) bool {
	return strings.Contains(act, "microsoft.resourcegraph/resources")
}

func isAcrPullAction(act string) bool {
	if !strings.Contains(act, "containerregistry/registries") {
		return false
	}
	return strings.Contains(act, "/pull") || strings.HasSuffix(act, "/read") || strings.Contains(act, "/read")
}

func isEventHubsReceiveAction(act string) bool {
	if !strings.Contains(act, "eventhub") {
		return false
	}
	return strings.Contains(act, "/receive") || strings.HasSuffix(act, "/read") || strings.Contains(act, "/read")
}

func roleHasGUID(role, guid string) bool {
	guid = strings.ToLower(guid)
	return role == guid || strings.HasSuffix(role, "/"+guid)
}

// Built-in role definition IDs (Azure well-known).
const (
	RoleOwner       = "/providers/Microsoft.Authorization/roleDefinitions/" + guidOwner
	RoleContributor = "/providers/Microsoft.Authorization/roleDefinitions/" + guidContributor
	RoleReader      = "/providers/Microsoft.Authorization/roleDefinitions/" + guidReader
	// RoleLogAnalyticsReader is Microsoft.Authorization role 73c42c96-874c-492b-b04d-ab87d138a893.
	RoleLogAnalyticsReader = "/providers/Microsoft.Authorization/roleDefinitions/" + guidLogAnalyticsReader
	// RoleMonitoringReader is Microsoft.Authorization role 43d0d8ad-25c7-4714-9337-8ba259a9fe05.
	RoleMonitoringReader = "/providers/Microsoft.Authorization/roleDefinitions/" + guidMonitoringReader
	// RoleAcrPull is recognized for registries/read and pull/read. Registry V2 docker pull is not implemented.
	RoleAcrPull = "/providers/Microsoft.Authorization/roleDefinitions/" + guidAcrPull
	// RoleEventHubsDataReceiver grants Event Hubs receive/read data-plane actions.
	RoleEventHubsDataReceiver = "/providers/Microsoft.Authorization/roleDefinitions/" + guidEventHubsDataReceiver
	// RoleLogAnalyticsDataReader is the narrower workspace query role (3b03c2da-...).
	RoleLogAnalyticsDataReader = "/providers/Microsoft.Authorization/roleDefinitions/" + guidLogAnalyticsDataReader
)

const (
	guidOwner                   = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	guidContributor             = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	guidReader                  = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	guidLogAnalyticsReader      = "73c42c96-874c-492b-b04d-ab87d138a893"
	guidLogAnalyticsReaderAlias = "73c42c96-874c-492b-b04d-ab87d988a1e9"
	guidMonitoringReader        = "43d0d8ad-25c7-4714-9337-8ba259a9fe05"
	guidLogAnalyticsDataReader  = "3b03c2da-16b3-4a49-8834-0f8130efdd3b"
	guidAcrPull                 = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
	guidEventHubsDataOwner      = "f526a384-b744-4348-a86b-d3d1f7ce3260"
	guidEventHubsDataReceiver   = "a638d3c7-ad44-4d07-a2c2-6d98be95d4e5"
)
