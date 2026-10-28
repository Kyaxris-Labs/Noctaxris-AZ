package config

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/compute"
)

const (
	EnvAllowNonLoopbackListen = "NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN"
	EnvCloudHosts             = "NOCTAXRIS_AZ_CLOUD_HOSTS"
	EnvLabForensics           = "NOCTAXRIS_AZ_LAB_FORENSICS"
	EnvActivityInject         = "NOCTAXRIS_AZ_ACTIVITY_INJECT"
	EnvLogsInject             = "NOCTAXRIS_AZ_LOGS_INJECT"
	EnvDefenderInject         = "NOCTAXRIS_AZ_DEFENDER_INJECT"
	EnvStripProduct           = "NOCTAXRIS_AZ_STRIP_PRODUCT"
	EnvPublicURL              = "NOCTAXRIS_AZ_PUBLIC_URL"
	EnvTLSAuto                = "NOCTAXRIS_AZ_TLS_AUTO"

	DefaultListenAddr           = "127.0.0.1:4599"
	DefaultAMQPListenAddr       = "127.0.0.1:5672"
	DefaultCloudHostsListenAddr = "127.0.0.1:8443"
	DefaultDataRoot             = "/var/lib/noctaxris-az"
	// Fixed lab GUIDs (not secrets).
	DefaultTenantID       = "00000000-0000-0000-0000-000000000001"
	DefaultSubscriptionID = "00000000-0000-0000-0000-000000000002"

	productOpsPathPrefix = "/_noctaxris-az"
	labOpsPathPrefix     = "/_lab"
	productLabDisplay    = "Noctaxris-AZ Lab"
	stripLabDisplay      = "Lab"
	productLabCACN       = "Noctaxris-AZ Lab CA"
	stripLabCACN         = "Lab CA"
	productLabCAOrg      = "Noctaxris-AZ"
	stripLabCAOrg        = "Lab"
)

const (
	exampleRootClientID    = "00000000-0000-0000-0000-00000000root"
	exampleRootAccessToken = "noctaxris-az-example-root-token"
	azuriteAccountName     = "devstoreaccount1"
	azuriteAccountKey      = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)

// Config holds process configuration from NOCTAXRIS_AZ_* environment variables.
type Config struct {
	ListenAddr             string
	AMQPListenAddr         string
	DataRoot               string
	MasterKeyPath          string
	TLSCertFile            string
	TLSKeyFile             string
	TLSAuto                bool
	PublicURL              string
	RootClientID           string
	RootAccessToken        string
	TenantID               string
	SubscriptionID         string
	AllowNonLoopbackListen bool
	CloudHosts             bool
	CloudHostsListen       string
	DockerHost             string
	DockerTLSCertPath      string
	// LabForensics enables /_noctaxris-az/lab clock and BulkSeed (default off).
	LabForensics bool
	// ActivityInject enables Activity Log inject (default off).
	ActivityInject bool
	// LogsInject enables named Log Analytics table inject and POST /loganalytics/{workspace}/ingest/{table} (default off).
	LogsInject bool
	// DefenderInject enables ARG SecurityResources assessment inject (default off).
	DefenderInject bool
	// StripProduct hides product-branded ops paths and display labels (default off).
	StripProduct bool
}

// LoadFromEnv reads configuration from the process environment.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:             getenv("NOCTAXRIS_AZ_LISTEN", DefaultListenAddr),
		AMQPListenAddr:         getenv("NOCTAXRIS_AZ_AMQP_LISTEN", DefaultAMQPListenAddr),
		DataRoot:               getenv("NOCTAXRIS_AZ_DATA_ROOT", DefaultDataRoot),
		MasterKeyPath:          getenv("NOCTAXRIS_AZ_MASTER_KEY_FILE", ""),
		TLSCertFile:            getenv("NOCTAXRIS_AZ_TLS_CERT", ""),
		TLSKeyFile:             getenv("NOCTAXRIS_AZ_TLS_KEY", ""),
		TLSAuto:                envTruthy(EnvTLSAuto),
		PublicURL:              strings.TrimSpace(getenv(EnvPublicURL, "")),
		RootClientID:           getenv("NOCTAXRIS_AZ_ROOT_CLIENT_ID", ""),
		RootAccessToken:        getenv("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN", ""),
		TenantID:               getenv("NOCTAXRIS_AZ_TENANT_ID", DefaultTenantID),
		SubscriptionID:         getenv("NOCTAXRIS_AZ_SUBSCRIPTION_ID", DefaultSubscriptionID),
		AllowNonLoopbackListen: envTruthy(EnvAllowNonLoopbackListen),
		CloudHosts:             envTruthy(EnvCloudHosts),
		CloudHostsListen:       getenv("NOCTAXRIS_AZ_CLOUD_HOSTS_LISTEN", ""),
		DockerHost:             getenv("NOCTAXRIS_AZ_DOCKER_HOST", ""),
		DockerTLSCertPath:      getenv("NOCTAXRIS_AZ_DOCKER_CERT_PATH", ""),
		LabForensics:           envTruthy(EnvLabForensics),
		ActivityInject:         envTruthy(EnvActivityInject),
		LogsInject:             envTruthy(EnvLogsInject),
		DefenderInject:         envTruthy(EnvDefenderInject),
		StripProduct:           envTruthy(EnvStripProduct),
	}
	if cfg.CloudHosts && strings.TrimSpace(cfg.CloudHostsListen) == "" {
		cfg.CloudHostsListen = DefaultCloudHostsListenAddr
	}
	if err := compute.ValidateDockerHost(cfg.DockerHost, cfg.DockerTLSCertPath); err != nil {
		return Config{}, err
	}
	if err := ValidateListenSecurity(cfg); err != nil {
		return Config{}, err
	}
	if err := ValidateAMQPListenSecurity(cfg); err != nil {
		return Config{}, err
	}
	if err := ValidateCloudHostsListen(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envTruthy(key string) bool {
	return strings.EqualFold(os.Getenv(key), "1") ||
		strings.EqualFold(os.Getenv(key), "true")
}

// StripProductEnabled reports whether NOCTAXRIS_AZ_STRIP_PRODUCT is truthy.
func StripProductEnabled() bool {
	return envTruthy(EnvStripProduct)
}

// OpsPathPrefix returns the ops path prefix for health/ready/version.
func OpsPathPrefix() string {
	if StripProductEnabled() {
		return labOpsPathPrefix
	}
	return productOpsPathPrefix
}

// OpsPathPrefix returns the ops path prefix for this config.
func (c Config) OpsPathPrefix() string {
	if c.StripProduct {
		return labOpsPathPrefix
	}
	return productOpsPathPrefix
}

// OIDCLabPathPrefix returns the preferred lab OIDC issuer path under the active ops prefix.
func OIDCLabPathPrefix() string {
	return OpsPathPrefix() + "/oidc-lab"
}

// OIDCLabPathPrefix returns the preferred lab OIDC issuer path for this config.
func (c Config) OIDCLabPathPrefix() string {
	return c.OpsPathPrefix() + "/oidc-lab"
}

// OIDCLabPathPrefixes returns both lab OIDC path prefixes (product and strip) for dual mount/verify.
func OIDCLabPathPrefixes() []string {
	return []string{productOpsPathPrefix + "/oidc-lab", labOpsPathPrefix + "/oidc-lab"}
}

// ReadyPath is the readiness probe path for the process environment.
func ReadyPath() string {
	return OpsPathPrefix() + "/ready"
}

// ReadyPath is the readiness probe path for this config.
func (c Config) ReadyPath() string {
	return c.OpsPathPrefix() + "/ready"
}

// HealthPath is the liveness probe path for this config.
func (c Config) HealthPath() string {
	return c.OpsPathPrefix() + "/health"
}

// VersionPath is the version probe path for this config.
func (c Config) VersionPath() string {
	return c.OpsPathPrefix() + "/version"
}

// LabDisplayName is the subscription/tenant/org display name for the process environment.
func LabDisplayName() string {
	if StripProductEnabled() {
		return stripLabDisplay
	}
	return productLabDisplay
}

// LabDisplayName is the subscription/tenant/org display name for this config.
func (c Config) LabDisplayName() string {
	if c.StripProduct {
		return stripLabDisplay
	}
	return productLabDisplay
}

// LabCACommonName is the lab CA certificate CN for the process environment.
func LabCACommonName() string {
	if v := strings.TrimSpace(os.Getenv("NOCTAXRIS_AZ_CA_CN")); v != "" {
		return v
	}
	if StripProductEnabled() {
		return stripLabCACN
	}
	return productLabCACN
}

// LabCAOrganization is the lab CA Organization for the process environment.
func LabCAOrganization() string {
	if v := strings.TrimSpace(os.Getenv("NOCTAXRIS_AZ_CA_ORG")); v != "" {
		return v
	}
	if StripProductEnabled() {
		return stripLabCAOrg
	}
	return productLabCAOrg
}

// ExampleRootCredentials reports whether id and token match docker/.env.example.
func ExampleRootCredentials(clientID, token string) bool {
	return clientID == exampleRootClientID && token == exampleRootAccessToken
}

// AzuriteWellKnownCredentials reports the classic Azurite account/key pair.
func AzuriteWellKnownCredentials(account, key string) bool {
	return account == azuriteAccountName && key == azuriteAccountKey
}

// ListenIsLoopback reports whether addr binds only loopback.
func ListenIsLoopback(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			return false
		}
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// TLSEnabled reports whether both TLS PEM paths are set, or TLS auto is on.
func (c Config) TLSEnabled() bool {
	if strings.TrimSpace(c.TLSCertFile) != "" && strings.TrimSpace(c.TLSKeyFile) != "" {
		return true
	}
	return c.TLSAuto
}

// PublicBase is the client-facing origin for OIDC iss, cloud metadata, and CLI register.
// Prefer NOCTAXRIS_AZ_PUBLIC_URL. Otherwise rewrite wildcard binds to loopback.
// RequestOrigin follows the request Host when that override is empty and cloud-hosts mode is off.
func (c Config) PublicBase() string {
	if u := strings.TrimSpace(c.PublicURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	if c.CloudHosts {
		return "https://login.microsoftonline.com"
	}
	scheme := "http"
	if c.TLSEnabled() {
		scheme = "https"
	}
	return scheme + "://" + publicListenHost(c.ListenAddr)
}

// ResourceManagerBase is the ARM origin advertised in /metadata/endpoints.
func (c Config) ResourceManagerBase() string {
	if u := strings.TrimSpace(c.PublicURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	if c.CloudHosts {
		return "https://management.azure.com"
	}
	return c.PublicBase()
}

func publicListenHost(listenAddr string) string {
	host := strings.TrimSpace(listenAddr)
	switch {
	case strings.HasPrefix(host, "0.0.0.0:"):
		return "127.0.0.1" + strings.TrimPrefix(host, "0.0.0.0")
	case strings.HasPrefix(host, "[::]:"):
		return "[::1]" + strings.TrimPrefix(host, "[::]")
	case strings.HasPrefix(host, ":"):
		return "127.0.0.1" + host
	default:
		return host
	}
}

// ValidateListenSecurity fails closed for non-loopback HTTP without TLS/allow.
func ValidateListenSecurity(c Config) error {
	if ListenIsLoopback(c.ListenAddr) {
		return nil
	}
	if c.TLSEnabled() {
		return nil
	}
	if c.AllowNonLoopbackListen || envTruthy(EnvAllowNonLoopbackListen) {
		return nil
	}
	return fmt.Errorf("NOCTAXRIS_AZ_LISTEN %q is non-loopback without TLS; set NOCTAXRIS_AZ_TLS_CERT and NOCTAXRIS_AZ_TLS_KEY, or %s=1 when host publish stays loopback (Compose)",
		c.ListenAddr, EnvAllowNonLoopbackListen)
}

// ValidateCloudHostsListen fails closed for non-loopback cloud-hosts TLS without allow.
func ValidateCloudHostsListen(c Config) error {
	if !c.CloudHosts {
		return nil
	}
	if ListenIsLoopback(c.CloudHostsListen) {
		return nil
	}
	if c.AllowNonLoopbackListen || envTruthy(EnvAllowNonLoopbackListen) {
		return nil
	}
	return fmt.Errorf("NOCTAXRIS_AZ_CLOUD_HOSTS_LISTEN %q is non-loopback; keep loopback or set %s=1 when host publish stays loopback",
		c.CloudHostsListen, EnvAllowNonLoopbackListen)
}

// IssuerBase is the OIDC issuer origin (iss / discovery). Uses PublicBase.
func (c Config) IssuerBase() string {
	return c.PublicBase()
}

// PinPublicOrigin reports that discovery must keep PublicBase.
// True when NOCTAXRIS_AZ_PUBLIC_URL is set, or when cloud-hosts mode advertises login.microsoftonline.com.
func (c Config) PinPublicOrigin() bool {
	return strings.TrimSpace(c.PublicURL) != "" || c.CloudHosts
}

// RequestOrigin is the origin discovery and issuer URLs advertise for this request.
// A pinned public origin wins. Otherwise the request Host is used (http unless r.TLS is set).
// An empty Host falls back to PublicBase.
func (c Config) RequestOrigin(r *http.Request) string {
	if c.PinPublicOrigin() {
		return c.PublicBase()
	}
	if o := OriginFromRequest(r); o != "" {
		return o
	}
	return c.PublicBase()
}

// OriginFromRequest is scheme://host from r. Scheme is http unless r.TLS is set.
// An empty or rejected Host returns an empty string.
func OriginFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := strings.TrimSpace(r.Host)
	if !advertisedHostOK(host) {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + host
}

// RewriteLoopbackOrigin replaces scheme and host when raw is an absolute URL whose host is loopback.
// The replacement is OriginFromRequest. Other URLs, and requests with no usable Host, are unchanged.
func RewriteLoopbackOrigin(raw string, r *http.Request) string {
	origin := OriginFromRequest(r)
	if origin == "" {
		return raw
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || !ListenIsLoopback(u.Host) {
		return raw
	}
	o, err := url.Parse(origin)
	if err != nil || o.Scheme == "" || o.Host == "" {
		return raw
	}
	u.Scheme = o.Scheme
	u.Host = o.Host
	return u.String()
}

// LabOIDCIssuerPath returns the lab OIDC path when raw is an http(s) URL whose path is
// exactly /_lab/oidc-lab or /_noctaxris-az/oidc-lab. Host is ignored.
func LabOIDCIssuerPath(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	path := strings.TrimRight(u.Path, "/")
	for _, pref := range OIDCLabPathPrefixes() {
		if path == pref {
			return pref, true
		}
	}
	return "", false
}

// LabOIDCIssuersMatch reports whether two federated issuer strings refer to the same issuer.
// Equal strings match. Lab OIDC URLs also match when both paths are the same lab path, ignoring host.
// Unrelated issuers do not match.
func LabOIDCIssuersMatch(stored, presented string) bool {
	if stored == presented {
		return true
	}
	sp, sok := LabOIDCIssuerPath(stored)
	pp, pok := LabOIDCIssuerPath(presented)
	return sok && pok && sp == pp
}

func advertisedHostOK(host string) bool {
	if host == "" || len(host) > 512 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c <= ' ' || c == '/' || c == '\\' || c == '@' || c == '?' || c == '#' || c == '%' {
			return false
		}
	}
	return true
}

// CAPath returns the ops path that serves the lab CA PEM.
func (c Config) CAPath() string {
	return c.OpsPathPrefix() + "/ca.pem"
}

// ValidateAMQPListenSecurity fails closed for non-loopback AMQP without allow.
func ValidateAMQPListenSecurity(c Config) error {
	if ListenIsLoopback(c.AMQPListenAddr) {
		return nil
	}
	if c.AllowNonLoopbackListen || envTruthy(EnvAllowNonLoopbackListen) {
		return nil
	}
	return fmt.Errorf("NOCTAXRIS_AZ_AMQP_LISTEN %q is non-loopback; set %s=1 when host publish stays loopback (Compose)",
		c.AMQPListenAddr, EnvAllowNonLoopbackListen)
}
