// Package armprops helps theatre ARM handlers present resource properties safely.
package armprops

import "strings"

// Public returns a shallow copy of props with secret-bearing keys omitted.
// Stored PropertiesJSON may still hold secrets for lab recreate; GET/list/PUT
// responses must not echo them to Readers (or any caller) without listKeys-class auth.
func Public(props map[string]any) map[string]any {
	if props == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		if isSecretPropertyKey(k) {
			continue
		}
		out[k] = v
	}
	return out
}

func isSecretPropertyKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	case "administratorloginpassword",
		"password",
		"primarykey",
		"secondarykey",
		"primarymasterkey",
		"secondarymasterkey",
		"primaryreadonlymasterkey",
		"secondaryreadonlymasterkey",
		"connectionstring",
		"primaryconnectionstring",
		"secondaryconnectionstring",
		"accesskey",
		"accesskeys",
		"sharedaccesskey",
		"clientsecret",
		"secret",
		"secrets",
		"kubeconfig":
		return true
	default:
		return strings.Contains(k, "password") ||
			strings.HasSuffix(k, "connectionstring") ||
			strings.HasSuffix(k, "masterkey") ||
			(strings.Contains(k, "accesskey") && !strings.Contains(k, "accesskeyenabled"))
	}
}
