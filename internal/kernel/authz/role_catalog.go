package authz

// BuiltInRole is a marketed built-in role definition for ARM list/get.
type BuiltInRole struct {
	Name        string
	RoleName    string
	Description string
}

// BuiltInRoles returns the lab catalogue of built-in role definitions.
func BuiltInRoles() []BuiltInRole {
	return []BuiltInRole{
		{Name: guidOwner, RoleName: "Owner", Description: "Grants full access to manage all resources, including the ability to assign roles"},
		{Name: guidContributor, RoleName: "Contributor", Description: "Grants full access to manage all resources, but does not allow you to assign roles"},
		{Name: guidReader, RoleName: "Reader", Description: "View all resources, but does not allow you to make any changes"},
		{Name: guidLogAnalyticsReader, RoleName: "Log Analytics Reader", Description: "View Log Analytics data and settings"},
		{Name: guidMonitoringReader, RoleName: "Monitoring Reader", Description: "Read monitoring data"},
		{Name: guidLogAnalyticsDataReader, RoleName: "Log Analytics Data Reader", Description: "Read Log Analytics workspace data"},
		{Name: guidAcrPull, RoleName: "AcrPull", Description: "Pull artifacts from Azure Container Registry"},
		{Name: guidStorageBlobDataOwner, RoleName: "Storage Blob Data Owner", Description: "Full access to Azure Storage blob containers and data"},
		{Name: guidStorageBlobDataContributor, RoleName: "Storage Blob Data Contributor", Description: "Read, write, and delete Azure Storage containers and blobs"},
		{Name: guidStorageBlobDataReader, RoleName: "Storage Blob Data Reader", Description: "Read and list Azure Storage containers and blobs"},
		{Name: guidStorageQueueDataContributor, RoleName: "Storage Queue Data Contributor", Description: "Read, write, and delete Azure Storage queues and queue messages"},
		{Name: guidStorageQueueDataReader, RoleName: "Storage Queue Data Reader", Description: "Read and list Azure Storage queues and queue messages"},
		{Name: guidStorageTableDataContributor, RoleName: "Storage Table Data Contributor", Description: "Read, write, and delete Azure Storage tables and entities"},
		{Name: guidStorageTableDataReader, RoleName: "Storage Table Data Reader", Description: "Read and list Azure Storage tables and entities"},
		{Name: guidEventHubsDataOwner, RoleName: "Azure Event Hubs Data Owner", Description: "Allows for full access to Azure Event Hubs data"},
		{Name: guidEventHubsDataSender, RoleName: "Azure Event Hubs Data Sender", Description: "Allows send access to Azure Event Hubs data"},
		{Name: guidEventHubsDataReceiver, RoleName: "Azure Event Hubs Data Receiver", Description: "Allows receive access to Azure Event Hubs data"},
		{Name: guidKeyVaultAdministrator, RoleName: "Key Vault Administrator", Description: "Perform all data plane operations on a key vault"},
		{Name: guidKeyVaultSecretsOfficer, RoleName: "Key Vault Secrets Officer", Description: "Perform any action on Key Vault secrets except manage permissions"},
		{Name: guidKeyVaultSecretsUser, RoleName: "Key Vault Secrets User", Description: "Read secret contents"},
		{Name: guidAppConfigDataReader, RoleName: "App Configuration Data Reader", Description: "Read App Configuration data"},
		{Name: guidAppConfigDataOwner, RoleName: "App Configuration Data Owner", Description: "Full access to App Configuration data"},
		{Name: guidServiceBusDataOwner, RoleName: "Azure Service Bus Data Owner", Description: "Allows for full access to Azure Service Bus resources"},
		{Name: guidServiceBusDataSender, RoleName: "Azure Service Bus Data Sender", Description: "Allows for send access to Azure Service Bus resources"},
		{Name: guidServiceBusDataReceiver, RoleName: "Azure Service Bus Data Receiver", Description: "Allows for receive access to Azure Service Bus resources"},
		{Name: guidEventGridDataSender, RoleName: "EventGrid Data Sender", Description: "Allows send access to Event Grid topic events"},
		{Name: guidCognitiveOpenAIUser, RoleName: "Cognitive Services OpenAI User", Description: "Read models and run inference"},
		{Name: guidAKSClusterAdmin, RoleName: "Azure Kubernetes Service Cluster Admin Role", Description: "List cluster admin credential"},
		{Name: guidAKSClusterUser, RoleName: "Azure Kubernetes Service Cluster User Role", Description: "List cluster user credential"},
	}
}

// RoleDefinitionARM returns an ARM roleDefinitions resource document.
func RoleDefinitionARM(scopePrefix string, role BuiltInRole) map[string]any {
	id := scopePrefix + "/providers/Microsoft.Authorization/roleDefinitions/" + role.Name
	return map[string]any{
		"id":   id,
		"type": "Microsoft.Authorization/roleDefinitions",
		"name": role.Name,
		"properties": map[string]any{
			"roleName":         role.RoleName,
			"type":             "BuiltInRole",
			"description":      role.Description,
			"assignableScopes": []string{"/"},
		},
	}
}
