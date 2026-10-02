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
	case roleHasGUID(role, guidOwner):
		// Owner covers ARM control plane. Dedicated data-plane actions stay on data roles.
		return !isDedicatedDataPlaneAction(act)
	case roleHasGUID(role, guidContributor):
		return !strings.Contains(act, "authorization/roleassignments") && !isDedicatedDataPlaneAction(act)
	case roleHasGUID(role, guidLogAnalyticsDataReader):
		return isWorkspaceQueryAction(act) || act == "microsoft.operationalinsights/workspaces/read"
	case isLogAnalyticsReaderRole(role):
		return isReadLikeAction(act) || isWorkspaceQueryAction(act)
	case roleHasGUID(role, guidAcrPull):
		return isAcrPullAction(act)
	case roleHasGUID(role, guidStorageBlobDataOwner):
		return isStorageBlobDataAction(act)
	case roleHasGUID(role, guidStorageBlobDataContributor):
		return isStorageBlobDataAction(act)
	case roleHasGUID(role, guidStorageBlobDataReader):
		return isStorageBlobDataReadAction(act)
	case roleHasGUID(role, guidStorageQueueDataContributor):
		return isStorageQueueDataAction(act)
	case roleHasGUID(role, guidStorageQueueDataReader):
		return isStorageQueueDataReadAction(act)
	case roleHasGUID(role, guidStorageTableDataContributor):
		return isStorageTableDataAction(act)
	case roleHasGUID(role, guidStorageTableDataReader):
		return isStorageTableDataReadAction(act)
	case roleHasGUID(role, guidEventHubsDataOwner) || roleHasGUID(role, guidEventHubsDataOwnerAlias):
		return isEventHubsDataPlaneAction(act)
	case roleHasGUID(role, guidEventHubsDataReceiver) || roleHasGUID(role, guidEventHubsDataReceiverAlias):
		return isEventHubsReceiveAction(act)
	case roleHasGUID(role, guidServiceBusDataOwner):
		return isServiceBusDataAction(act)
	case roleHasGUID(role, guidServiceBusDataSender):
		return isServiceBusSendAction(act)
	case roleHasGUID(role, guidServiceBusDataReceiver):
		return isServiceBusReceiveAction(act)
	case roleHasGUID(role, guidEventGridDataSender):
		return isEventGridSendAction(act)
	case roleHasGUID(role, guidAppConfigDataOwner):
		return isAppConfigDataPlaneAction(act)
	case roleHasGUID(role, guidAppConfigDataReader):
		return isAppConfigDataReadAction(act)
	case roleHasGUID(role, guidCosmosDataContributor) || roleHasGUID(role, guidCosmosDataContributorAlias):
		return isCosmosDataPlaneAction(act)
	case roleHasGUID(role, guidCosmosDataReader) || roleHasGUID(role, guidCosmosDataReaderAlias):
		return isCosmosDataReadAction(act)
	case roleHasGUID(role, guidCognitiveOpenAIUser):
		return isCognitiveDataPlaneAction(act)
	case roleHasGUID(role, guidAKSClusterAdmin):
		return isAKSAdminCredentialAction(act)
	case roleHasGUID(role, guidAKSClusterUser):
		return isAKSUserCredentialAction(act)
	case roleHasGUID(role, guidKeyVaultAdministrator):
		return strings.Contains(act, "microsoft.keyvault/")
	case roleHasGUID(role, guidKeyVaultSecretsOfficer):
		return isKeyVaultSecretsWriteAction(act) || isKeyVaultSecretsReadAction(act)
	case roleHasGUID(role, guidKeyVaultSecretsUser):
		return isKeyVaultSecretsReadAction(act)
	case isReaderLikeRole(role):
		return isReadLikeAction(act) && !isSecretDisclosureAction(act)
	default:
		return false
	}
}

func isLogAnalyticsReaderRole(role string) bool {
	if roleHasGUID(role, guidLogAnalyticsReader) || roleHasGUID(role, guidLogAnalyticsReaderAlias) {
		return true
	}
	return strings.Contains(role, "log analytics reader")
}

func isReaderLikeRole(role string) bool {
	if isLogAnalyticsReaderRole(role) {
		return false
	}
	if roleHasGUID(role, guidReader) || roleHasGUID(role, guidMonitoringReader) {
		return true
	}
	if role == "reader" || strings.HasSuffix(role, "/reader") {
		return true
	}
	return strings.Contains(role, "monitoring reader")
}

func isReadLikeAction(act string) bool {
	if isWorkspaceQueryAction(act) {
		return false
	}
	if isSecretDisclosureAction(act) {
		return false
	}
	// Dedicated data-plane reads (ACR pull, Storage blob/table, etc.) stay on data roles.
	if isDedicatedDataPlaneAction(act) {
		return false
	}
	if strings.HasSuffix(act, "/read") || strings.Contains(act, "/read/") || strings.Contains(act, "/read") {
		return true
	}
	return isResourceGraphRead(act)
}

func isSecretDisclosureAction(act string) bool {
	return strings.Contains(act, "/listkeys") ||
		strings.Contains(act, "/listconnectionstrings") ||
		strings.Contains(act, "authorizationrules/listkeys") ||
		isAKSCredentialAction(act) ||
		isAppConfigDataPlaneAction(act)
}

func isDedicatedDataPlaneAction(act string) bool {
	// AKS listCluster*Credential stays on Owner/Contributor (like listKeys); Reader is blocked via isSecretDisclosureAction.
	return isKeyVaultDataPlaneAction(act) ||
		isAppConfigDataPlaneAction(act) ||
		isCosmosDataPlaneAction(act) ||
		isServiceBusDataAction(act) ||
		isEventHubsDataPlaneAction(act) ||
		isEventGridSendAction(act) ||
		isCognitiveDataPlaneAction(act) ||
		isAcrPullAction(act) ||
		isStorageDataPlaneAction(act)
}

func isStorageDataPlaneAction(act string) bool {
	return isStorageBlobDataAction(act) || isStorageQueueDataAction(act) || isStorageTableDataAction(act)
}

func isStorageBlobDataAction(act string) bool {
	return strings.Contains(act, "microsoft.storage/storageaccounts/blobservices/")
}

func isStorageBlobDataReadAction(act string) bool {
	return isStorageBlobDataAction(act) && (strings.Contains(act, "/read") || strings.HasSuffix(act, "/get"))
}

func isStorageQueueDataAction(act string) bool {
	return strings.Contains(act, "microsoft.storage/storageaccounts/queueservices/")
}

func isStorageQueueDataReadAction(act string) bool {
	return isStorageQueueDataAction(act) && (strings.Contains(act, "/read") || strings.Contains(act, "/messages/read"))
}

func isStorageTableDataAction(act string) bool {
	return strings.Contains(act, "microsoft.storage/storageaccounts/tableservices/")
}

func isStorageTableDataReadAction(act string) bool {
	return isStorageTableDataAction(act) && (strings.Contains(act, "/read") || strings.Contains(act, "/entities/read"))
}

func isKeyVaultDataPlaneAction(act string) bool {
	return strings.Contains(act, "microsoft.keyvault/vaults/secrets/") ||
		strings.Contains(act, "microsoft.keyvault/vaults/keys/") ||
		strings.Contains(act, "microsoft.keyvault/vaults/certificates/")
}

func isAppConfigDataPlaneAction(act string) bool {
	return strings.Contains(act, "microsoft.appconfiguration/configurationstores/keyvalues/") ||
		strings.Contains(act, "microsoft.appconfiguration/configurationstores/featureflags/") ||
		strings.Contains(act, "microsoft.appconfiguration/configurationstores/snapshots/")
}

func isAppConfigDataReadAction(act string) bool {
	if !isAppConfigDataPlaneAction(act) {
		return false
	}
	return strings.Contains(act, "/read") || strings.HasSuffix(act, "/get")
}

func isCosmosDataPlaneAction(act string) bool {
	return strings.Contains(act, "microsoft.documentdb/databaseaccounts/sqldatabases/") ||
		strings.Contains(act, "microsoft.documentdb/databaseaccounts/docs/") ||
		(strings.Contains(act, "microsoft.documentdb/databaseaccounts/") &&
			(strings.Contains(act, "/items/") || strings.Contains(act, "/dbs/") || strings.Contains(act, "/colls/")))
}

func isCosmosDataReadAction(act string) bool {
	if !isCosmosDataPlaneAction(act) {
		return false
	}
	return strings.Contains(act, "/read") || strings.Contains(act, "/query") || strings.Contains(act, "/changefeed")
}

func isServiceBusDataAction(act string) bool {
	return strings.Contains(act, "microsoft.servicebus/") &&
		(strings.Contains(act, "/messages/") || strings.Contains(act, "/send") || strings.Contains(act, "/receive") ||
			strings.Contains(act, "queues/messages") || strings.Contains(act, "topics/messages"))
}

func isServiceBusSendAction(act string) bool {
	return isServiceBusDataAction(act) && (strings.Contains(act, "/send") || strings.Contains(act, "/write"))
}

func isServiceBusReceiveAction(act string) bool {
	return isServiceBusDataAction(act) && (strings.Contains(act, "/receive") || strings.Contains(act, "/read"))
}

func isEventGridSendAction(act string) bool {
	// Event subscription CRUD is ARM control plane; only topic publish is data-plane send.
	return strings.Contains(act, "microsoft.eventgrid/") &&
		(strings.Contains(act, "/events/send") ||
			strings.Contains(act, "topics/send") || strings.HasSuffix(act, "/send/action"))
}

func isCognitiveDataPlaneAction(act string) bool {
	return strings.Contains(act, "microsoft.cognitiveservices/accounts/") &&
		(strings.Contains(act, "/openai/") || strings.Contains(act, "/deployments/") ||
			strings.Contains(act, "chat/completions") || strings.Contains(act, "/inference"))
}

func isAKSCredentialAction(act string) bool {
	return isAKSAdminCredentialAction(act) || isAKSUserCredentialAction(act)
}

func isAKSAdminCredentialAction(act string) bool {
	return strings.Contains(act, "microsoft.containerservice/managedclusters/listclusteradmincredential")
}

func isAKSUserCredentialAction(act string) bool {
	return strings.Contains(act, "microsoft.containerservice/managedclusters/listclusterusercredential")
}

func isKeyVaultSecretsReadAction(act string) bool {
	return strings.Contains(act, "microsoft.keyvault/vaults/secrets/get") ||
		strings.Contains(act, "microsoft.keyvault/vaults/secrets/read") ||
		act == "microsoft.keyvault/vaults/secrets/getsecret/action"
}

func isKeyVaultSecretsWriteAction(act string) bool {
	return strings.Contains(act, "microsoft.keyvault/vaults/secrets/set") ||
		strings.Contains(act, "microsoft.keyvault/vaults/secrets/write") ||
		strings.Contains(act, "microsoft.keyvault/vaults/secrets/delete") ||
		strings.Contains(act, "microsoft.keyvault/vaults/secrets/backup") ||
		strings.Contains(act, "microsoft.keyvault/vaults/secrets/restore") ||
		strings.Contains(act, "microsoft.keyvault/vaults/secrets/purge") ||
		strings.Contains(act, "microsoft.keyvault/vaults/secrets/recover")
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
	// AcrPull is pull/read only. ARM registries/read stays on Reader/Contributor.
	return strings.Contains(act, "/pull")
}

func isEventHubsReceiveAction(act string) bool {
	if !strings.Contains(act, "eventhub") {
		return false
	}
	if isEventHubsControlPlaneAction(act) {
		return false
	}
	return strings.Contains(act, "/receive") || strings.Contains(act, "/messages/receive")
}

// isEventHubsDataPlaneAction is Azure Event Hubs Data Owner: send/receive on hubs, not ARM namespace CRUD/read.
func isEventHubsDataPlaneAction(act string) bool {
	if !strings.Contains(act, "eventhub") {
		return false
	}
	if isEventHubsControlPlaneAction(act) {
		return false
	}
	return strings.Contains(act, "/receive") ||
		strings.Contains(act, "/send") ||
		strings.Contains(act, "/messages/")
}

func isEventHubsControlPlaneAction(act string) bool {
	return strings.Contains(act, "namespaces/write") ||
		strings.Contains(act, "namespaces/delete") ||
		strings.Contains(act, "eventhubs/write") ||
		strings.Contains(act, "eventhubs/delete") ||
		strings.Contains(act, "consumergroups/write") ||
		strings.Contains(act, "consumergroups/delete")
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
	// RoleAcrPull grants registries/pull/read (Registry V2 pull, not push).
	RoleAcrPull = "/providers/Microsoft.Authorization/roleDefinitions/" + guidAcrPull
	// Storage Blob / Queue / Table data-plane built-in roles (Azure published GUIDs).
	RoleStorageBlobDataOwner         = "/providers/Microsoft.Authorization/roleDefinitions/" + guidStorageBlobDataOwner
	RoleStorageBlobDataContributor   = "/providers/Microsoft.Authorization/roleDefinitions/" + guidStorageBlobDataContributor
	RoleStorageBlobDataReader        = "/providers/Microsoft.Authorization/roleDefinitions/" + guidStorageBlobDataReader
	RoleStorageQueueDataContributor  = "/providers/Microsoft.Authorization/roleDefinitions/" + guidStorageQueueDataContributor
	RoleStorageQueueDataReader       = "/providers/Microsoft.Authorization/roleDefinitions/" + guidStorageQueueDataReader
	RoleStorageTableDataContributor  = "/providers/Microsoft.Authorization/roleDefinitions/" + guidStorageTableDataContributor
	RoleStorageTableDataReader       = "/providers/Microsoft.Authorization/roleDefinitions/" + guidStorageTableDataReader
	// RoleEventHubsDataReceiver grants Event Hubs receive/read data-plane actions.
	RoleEventHubsDataReceiver = "/providers/Microsoft.Authorization/roleDefinitions/" + guidEventHubsDataReceiver
	// RoleEventHubsDataOwner grants Event Hubs send/receive/read data-plane actions (not ARM namespace write).
	RoleEventHubsDataOwner = "/providers/Microsoft.Authorization/roleDefinitions/" + guidEventHubsDataOwner
	// RoleLogAnalyticsDataReader is the narrower workspace query role (3b03c2da-...).
	RoleLogAnalyticsDataReader = "/providers/Microsoft.Authorization/roleDefinitions/" + guidLogAnalyticsDataReader
	// RoleKeyVaultSecretsUser grants Key Vault secret get on the data plane.
	RoleKeyVaultSecretsUser = "/providers/Microsoft.Authorization/roleDefinitions/" + guidKeyVaultSecretsUser
	// RoleKeyVaultSecretsOfficer grants Key Vault secret get/set/delete on the data plane.
	RoleKeyVaultSecretsOfficer = "/providers/Microsoft.Authorization/roleDefinitions/" + guidKeyVaultSecretsOfficer
	// RoleKeyVaultAdministrator grants Key Vault data-plane administration.
	RoleKeyVaultAdministrator = "/providers/Microsoft.Authorization/roleDefinitions/" + guidKeyVaultAdministrator
	// RoleAppConfigDataReader grants App Configuration keyValues/snapshots/featureFlags read.
	RoleAppConfigDataReader = "/providers/Microsoft.Authorization/roleDefinitions/" + guidAppConfigDataReader
	// RoleAppConfigDataOwner grants App Configuration data-plane read/write.
	RoleAppConfigDataOwner = "/providers/Microsoft.Authorization/roleDefinitions/" + guidAppConfigDataOwner
	// RoleCosmosDataReader grants Cosmos document read/query/changefeed.
	RoleCosmosDataReader = "/providers/Microsoft.Authorization/roleDefinitions/" + guidCosmosDataReader
	// RoleCosmosDataContributor grants Cosmos document read/write.
	RoleCosmosDataContributor = "/providers/Microsoft.Authorization/roleDefinitions/" + guidCosmosDataContributor
	// RoleServiceBusDataOwner grants Service Bus HTTP send and receive.
	RoleServiceBusDataOwner = "/providers/Microsoft.Authorization/roleDefinitions/" + guidServiceBusDataOwner
	// RoleServiceBusDataSender grants Service Bus HTTP send.
	RoleServiceBusDataSender = "/providers/Microsoft.Authorization/roleDefinitions/" + guidServiceBusDataSender
	// RoleServiceBusDataReceiver grants Service Bus HTTP receive.
	RoleServiceBusDataReceiver = "/providers/Microsoft.Authorization/roleDefinitions/" + guidServiceBusDataReceiver
	// RoleEventGridDataSender grants Event Grid topic publish.
	RoleEventGridDataSender = "/providers/Microsoft.Authorization/roleDefinitions/" + guidEventGridDataSender
	// RoleCognitiveOpenAIUser grants OpenAI chat completions theatre.
	RoleCognitiveOpenAIUser = "/providers/Microsoft.Authorization/roleDefinitions/" + guidCognitiveOpenAIUser
	// RoleAKSClusterAdminCredential grants listClusterAdminCredential.
	RoleAKSClusterAdminCredential = "/providers/Microsoft.Authorization/roleDefinitions/" + guidAKSClusterAdmin
	// RoleAKSClusterUserCredential grants listClusterUserCredential.
	RoleAKSClusterUserCredential = "/providers/Microsoft.Authorization/roleDefinitions/" + guidAKSClusterUser
)

const (
	guidOwner                      = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	guidContributor                = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	guidReader                     = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	guidLogAnalyticsReader         = "73c42c96-874c-492b-b04d-ab87d138a893"
	guidLogAnalyticsReaderAlias    = "73c42c96-874c-492b-b04d-ab87d988a1e9"
	guidMonitoringReader           = "43d0d8ad-25c7-4714-9337-8ba259a9fe05"
	guidLogAnalyticsDataReader     = "3b03c2da-16b3-4a49-8834-0f8130efdd3b"
	guidAcrPull                    = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
	guidStorageBlobDataOwner       = "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
	guidStorageBlobDataContributor = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
	guidStorageBlobDataReader      = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
	guidStorageQueueDataContributor = "974c5e8b-45b9-4653-ba55-5f855dd0fb88"
	guidStorageQueueDataReader      = "19e7f393-937e-4f77-808e-94535e297925"
	guidStorageTableDataContributor = "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
	guidStorageTableDataReader      = "76199698-9eea-4c19-bc75-cec21354c6b6"
	guidEventHubsDataOwner         = "f526a384-b230-433a-b45c-95f59c4a2dec"
	guidEventHubsDataOwnerAlias    = "f526a384-b744-4348-a86b-d3d1f7ce3260"
	guidEventHubsDataReceiver      = "a638d3c7-ab3a-418d-83e6-5f17a39d4fde"
	guidEventHubsDataReceiverAlias = "a638d3c7-ad44-4d07-a2c2-6d98be95d4e5"
	guidKeyVaultAdministrator      = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
	guidKeyVaultSecretsOfficer     = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
	guidKeyVaultSecretsUser        = "4633458b-17de-408a-b874-0445c86b69e6"
	// Azure built-in App Configuration Data Reader / Data Owner (Learn RBAC built-in roles).
	guidAppConfigDataReader = "516239f1-63e1-4d78-a4de-a74fb236a071"
	guidAppConfigDataOwner  = "5ae67dd6-50cb-40e7-96ff-dc2bfa4b606b"
	// Cosmos SQL RBAC built-in data roles (account-level ids reused as theatre GUIDs).
	guidCosmosDataReader           = "00000000-0000-0000-0000-000000000001"
	guidCosmosDataReaderAlias      = "fbdf93bf-df7d-467e-a4d2-9458aa1360c8"
	guidCosmosDataContributor      = "00000000-0000-0000-0000-000000000002"
	guidCosmosDataContributorAlias = "230815da-be43-4aae-9cb4-875f7bd000aa"
	guidServiceBusDataOwner        = "090c5cfd-751d-490a-894a-3ce6f1109419"
	guidServiceBusDataSender       = "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
	guidServiceBusDataReceiver     = "4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
	guidEventGridDataSender        = "d5a91429-5739-47e2-a06b-3470a27159e7"
	guidCognitiveOpenAIUser        = "5e0bd9bd-7b93-4f28-af87-19fc36ad61bd"
	guidAKSClusterAdmin            = "0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8"
	guidAKSClusterUser             = "4abbcc35-e782-43d8-92c5-2d3b4bd8b1c0"
)
