package authn

import "strings"

const (
	// AudienceGraph is the Microsoft Graph resource.
	AudienceGraph = "https://graph.microsoft.com"
	// AudienceGraphAppID is the Microsoft Graph application id.
	AudienceGraphAppID = "00000003-0000-0000-c000-000000000000"
	// AudienceAADGraph is the Azure AD Graph resource.
	AudienceAADGraph = "https://graph.windows.net"
	// AudienceAADGraphAppID is the Azure AD Graph application id.
	AudienceAADGraphAppID = "00000002-0000-0000-c000-000000000000"
	// AudienceARM is the Azure Resource Manager resource.
	AudienceARM = "https://management.azure.com"
	// AudienceARMLegacy is the ARM management.core resource.
	AudienceARMLegacy = "https://management.core.windows.net"
	// AudienceACR is the Azure Container Registry data-plane resource.
	AudienceACR = "https://containerregistry.azure.net"
	// AudienceACRService is the Registry V2 WWW-Authenticate service name.
	AudienceACRService = "containerregistry.azure.net"
	// AudienceVault is the Key Vault data-plane resource.
	AudienceVault = "https://vault.azure.net"
	// AudienceServiceBus is the Service Bus data-plane resource.
	AudienceServiceBus = "https://servicebus.azure.net"
	// AudienceEventHubs is the Event Hubs data-plane resource.
	AudienceEventHubs = "https://eventhubs.azure.net"
	// AudienceEventGrid is the Event Grid data-plane resource.
	AudienceEventGrid = "https://eventgrid.azure.net"
	// AudienceCosmos is the Cosmos DB data-plane resource.
	AudienceCosmos = "https://cosmos.azure.com"
	// AudienceAppConfig is the App Configuration data-plane resource.
	AudienceAppConfig = "https://azconfig.io"
	// AudienceCognitive is Cognitive Services / Azure OpenAI data plane.
	AudienceCognitive = "https://cognitiveservices.azure.com"
	// AudienceCommunication is Azure Communication Services data plane.
	AudienceCommunication = "https://communication.azure.com"
	// AudienceStorage is the Azure Storage data-plane resource.
	AudienceStorage = "https://storage.azure.com"
)

// NormalizeAudience trims space and a trailing slash for resource comparison.
func NormalizeAudience(aud string) string {
	return strings.TrimRight(strings.TrimSpace(aud), "/")
}

func audienceKind(aud string) string {
	switch NormalizeAudience(aud) {
	case NormalizeAudience(AudienceGraph), AudienceGraphAppID:
		return "graph"
	case NormalizeAudience(AudienceAADGraph), AudienceAADGraphAppID:
		return "aadgraph"
	case NormalizeAudience(AudienceARM), NormalizeAudience(AudienceARMLegacy):
		return "arm"
	case NormalizeAudience(AudienceACR), NormalizeAudience(AudienceACRService):
		return "acr"
	case NormalizeAudience(AudienceVault):
		return "vault"
	case NormalizeAudience(AudienceServiceBus):
		return "servicebus"
	case NormalizeAudience(AudienceEventHubs):
		return "eventhubs"
	case NormalizeAudience(AudienceEventGrid):
		return "eventgrid"
	case NormalizeAudience(AudienceCosmos):
		return "cosmos"
	case NormalizeAudience(AudienceAppConfig):
		return "appconfig"
	case NormalizeAudience(AudienceCognitive):
		return "cognitive"
	case NormalizeAudience(AudienceCommunication):
		return "communication"
	case NormalizeAudience(AudienceStorage):
		return "storage"
	default:
		return ""
	}
}

func (p Principal) allowsKind(kind string) bool {
	if p.IsRoot {
		return true
	}
	auds := p.normalizedAudiences()
	if len(auds) == 0 {
		return false
	}
	for _, a := range auds {
		if audienceKind(a) != kind {
			return false
		}
	}
	return true
}

func (p Principal) normalizedAudiences() []string {
	out := make([]string, 0, len(p.Audiences))
	for _, a := range p.Audiences {
		n := NormalizeAudience(a)
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

func (p Principal) audienceMatchesIssuer() bool {
	iss := NormalizeAudience(p.Issuer)
	if iss == "" {
		return false
	}
	for _, a := range p.normalizedAudiences() {
		if a == iss {
			return true
		}
	}
	return false
}

// AllowsGraph reports whether p may call Microsoft Graph, Azure AD Graph, or directory SOAP.
// Root skips audience. Non-root tokens must carry only Graph or Azure AD Graph resource audiences.
// ARM audiences and tokens whose aud equals iss are denied.
func (p Principal) AllowsGraph() bool {
	if p.IsRoot {
		return true
	}
	auds := p.normalizedAudiences()
	if len(auds) == 0 {
		return false
	}
	if p.audienceMatchesIssuer() {
		return false
	}
	for _, a := range auds {
		switch audienceKind(a) {
		case "graph", "aadgraph":
		default:
			return false
		}
	}
	return true
}

// AllowsARM reports whether p may call Azure Resource Manager.
// Root skips audience. Non-root tokens must carry only ARM resource audiences.
func (p Principal) AllowsARM() bool {
	if p.IsRoot {
		return true
	}
	auds := p.normalizedAudiences()
	if len(auds) == 0 {
		return false
	}
	for _, a := range auds {
		if audienceKind(a) != "arm" {
			return false
		}
	}
	return true
}

// AllowsVault reports whether p may call Key Vault data plane.
// Root skips audience. Non-root tokens must carry only the vault resource audience.
func (p Principal) AllowsVault() bool {
	return p.allowsKind("vault")
}

// AllowsServiceBus reports whether p may call Service Bus HTTP data plane.
func (p Principal) AllowsServiceBus() bool {
	return p.allowsKind("servicebus")
}

// AllowsEventHubs reports whether p may call Event Hubs data plane (capture theatre).
// ARM audience is accepted for AAD data-plane theatre. Opaque hashed tokens with no
// aud (lab directory tokens) are accepted. Graph and other non-Event-Hubs audiences are denied.
func (p Principal) AllowsEventHubs() bool {
	if p.IsRoot || p.AllowsARM() {
		return true
	}
	auds := p.normalizedAudiences()
	if len(auds) == 0 {
		return true
	}
	return p.allowsKind("eventhubs")
}

// AllowsEventGrid reports whether p may publish on Event Grid topics.
func (p Principal) AllowsEventGrid() bool {
	return p.allowsKind("eventgrid")
}

// AllowsCosmos reports whether p may call Cosmos document routes with Bearer.
// ARM audience is accepted for Entra data-plane theatre; Graph is denied.
func (p Principal) AllowsCosmos() bool {
	if p.IsRoot || p.AllowsARM() {
		return true
	}
	return p.allowsKind("cosmos")
}

// AllowsAppConfig reports whether p may call App Configuration data plane.
func (p Principal) AllowsAppConfig() bool {
	return p.allowsKind("appconfig")
}

// AllowsCognitive reports whether p may call Cognitive / OpenAI data plane.
func (p Principal) AllowsCognitive() bool {
	return p.allowsKind("cognitive")
}

// AllowsCommunication reports whether p may call Communication Services email send.
func (p Principal) AllowsCommunication() bool {
	return p.allowsKind("communication")
}

// AllowsStorage reports whether p may call Storage blob/queue/table data plane with Entra.
// Root skips audience. ARM audience is accepted for Entra data-plane theatre; Graph is denied.
func (p Principal) AllowsStorage() bool {
	if p.IsRoot || p.AllowsARM() {
		return true
	}
	return p.allowsKind("storage")
}

// AllowsRegistry reports whether p may call Registry V2 / oauth2 token theatre.
// Root skips audience. ARM directory Bearer is accepted (same token used for ARM).
// ACR resource audiences are accepted. Opaque hashed tokens with no aud (lab
// oauth2 mint that is not a JWT) are accepted. Graph and issuer-as-aud are denied.
func (p Principal) AllowsRegistry() bool {
	if p.IsRoot || p.AllowsARM() {
		return true
	}
	auds := p.normalizedAudiences()
	if len(auds) == 0 {
		return true
	}
	if p.audienceMatchesIssuer() {
		return false
	}
	for _, a := range auds {
		if audienceKind(a) == "acr" {
			return true
		}
	}
	return false
}
