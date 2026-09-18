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
	default:
		return ""
	}
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
