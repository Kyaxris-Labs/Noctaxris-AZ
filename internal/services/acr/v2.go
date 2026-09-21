package acr

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

const (
	distributionAPIVersion = "registry/2.0"
	distributionAPIHeader  = "Docker-Distribution-API-Version"
	acrServiceName         = "containerregistry.azure.net"
	defaultManifestType    = "application/vnd.docker.distribution.manifest.v2+json"
	maxV2Body              = 32 << 20
)

func (h *Handler) serveV2(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(distributionAPIHeader, distributionAPIVersion)
	kind, name, extra := parseRegistryV2Path(r.URL.Path)
	switch kind {
	case "ping":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeRegistryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "method not allowed")
			return
		}
		if !h.requireV2(w, r, name, false) {
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("{}"))
		}
	case "upload":
		switch r.Method {
		case http.MethodPost:
			h.startUpload(w, r, name)
		case http.MethodPut:
			h.putUpload(w, r, name, extra)
		default:
			w.Header().Set("Allow", "POST, PUT")
			writeRegistryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "method not allowed")
		}
	case "blob":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			h.getBlob(w, r, extra, r.Method == http.MethodHead)
		default:
			w.Header().Set("Allow", "GET, HEAD")
			writeRegistryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "method not allowed")
		}
	case "manifest":
		switch r.Method {
		case http.MethodPut:
			h.putManifest(w, r, name, extra)
		case http.MethodGet, http.MethodHead:
			h.getManifest(w, r, name, extra, r.Method == http.MethodHead)
		default:
			w.Header().Set("Allow", "GET, HEAD, PUT")
			writeRegistryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "method not allowed")
		}
	default:
		writeRegistryError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository name not known")
	}
}

func parseRegistryV2Path(path string) (kind, name, extra string) {
	p := strings.TrimSpace(path)
	p = strings.TrimPrefix(p, "/v2")
	if p == "" || p == "/" {
		return "ping", "", ""
	}
	p = strings.TrimPrefix(p, "/")
	if i := strings.Index(p, "/blobs/uploads"); i >= 0 {
		name = p[:i]
		rest := strings.Trim(p[i+len("/blobs/uploads"):], "/")
		return "upload", name, rest
	}
	if i := strings.Index(p, "/blobs/"); i >= 0 {
		return "blob", p[:i], p[i+len("/blobs/"):]
	}
	if i := strings.Index(p, "/manifests/"); i >= 0 {
		return "manifest", p[:i], p[i+len("/manifests/"):]
	}
	return "", "", ""
}

func (h *Handler) startUpload(w http.ResponseWriter, r *http.Request, name string) {
	if !h.requireV2(w, r, name, true) {
		return
	}
	if !validRepoName(name) {
		writeRegistryError(w, http.StatusBadRequest, "NAME_INVALID", "invalid repository name")
		return
	}
	id, err := h.Store.CreateACRUpload(name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	loc := "/v2/" + name + "/blobs/uploads/" + id
	w.Header().Set("Location", loc)
	w.Header().Set("Docker-Upload-UUID", id)
	w.Header().Set("Range", "0-0")
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) putUpload(w http.ResponseWriter, r *http.Request, name, id string) {
	if !h.requireV2(w, r, name, true) {
		return
	}
	digest := strings.TrimSpace(r.URL.Query().Get("digest"))
	if digest == "" || !validDigest(digest) {
		writeRegistryError(w, http.StatusBadRequest, "DIGEST_INVALID", "digest is required")
		return
	}
	ok, err := h.Store.ACRUploadExists(id)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		writeRegistryError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "upload uuid unknown")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxV2Body+1))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	if len(body) > maxV2Body {
		writeRegistryError(w, http.StatusBadRequest, "SIZE_INVALID", "blob too large")
		return
	}
	got := sha256Digest(body)
	if got != digest {
		writeRegistryError(w, http.StatusBadRequest, "DIGEST_INVALID", "digest mismatch")
		return
	}
	ct := r.Header.Get("Content-Type")
	if err := h.Store.FinishACRUpload(id, digest, body, ct); err != nil {
		if err == sql.ErrNoRows {
			writeRegistryError(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "upload uuid unknown")
			return
		}
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.Header().Set("Location", "/v2/"+name+"/blobs/"+digest)
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) getBlob(w http.ResponseWriter, r *http.Request, digest string, head bool) {
	name, _, _ := parseRegistryV2Path(r.URL.Path)
	if !h.requireV2(w, r, name, false) {
		return
	}
	if !validDigest(digest) {
		writeRegistryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown to registry")
		return
	}
	content, ct, ok, err := h.Store.GetACRBlob(digest)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		writeRegistryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown to registry")
		return
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.WriteHeader(http.StatusOK)
	if !head {
		_, _ = w.Write(content)
	}
}

func (h *Handler) putManifest(w http.ResponseWriter, r *http.Request, name, reference string) {
	if !h.requireV2(w, r, name, true) {
		return
	}
	if !validRepoName(name) || strings.TrimSpace(reference) == "" {
		writeRegistryError(w, http.StatusBadRequest, "NAME_INVALID", "invalid repository or reference")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxV2Body+1))
	if err != nil {
		azerrors.BadRequest(w, err.Error())
		return
	}
	if len(body) > maxV2Body {
		writeRegistryError(w, http.StatusBadRequest, "SIZE_INVALID", "manifest too large")
		return
	}
	digest := sha256Digest(body)
	media := r.Header.Get("Content-Type")
	if media == "" {
		media = defaultManifestType
	}
	if err := h.Store.PutACRManifest(name, reference, digest, body, media); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if reference != digest {
		if err := h.Store.PutACRManifest(name, digest, digest, body, media); err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
	}
	w.Header().Set("Location", "/v2/"+name+"/manifests/"+digest)
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) getManifest(w http.ResponseWriter, r *http.Request, name, reference string, head bool) {
	if !h.requireV2(w, r, name, false) {
		return
	}
	content, digest, media, ok, err := h.Store.GetACRManifest(name, reference)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		writeRegistryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
		return
	}
	if media == "" {
		media = defaultManifestType
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.WriteHeader(http.StatusOK)
	if !head {
		_, _ = w.Write(content)
	}
}

func (h *Handler) oauth2Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(distributionAPIHeader, distributionAPIVersion)
	p, err := h.authenticateRegistry(r)
	if err != nil {
		writeRegistryUnauthorized(w, r, "")
		return
	}
	if !p.AllowsRegistry() {
		writeRegistryError(w, http.StatusForbidden, "DENIED", "token audience is not allowed for registry")
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
	}
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if r.Method == http.MethodPost {
		if service == "" {
			service = strings.TrimSpace(r.Form.Get("service"))
		}
		if scope == "" {
			scope = strings.TrimSpace(r.Form.Get("scope"))
		}
	}
	if service == "" {
		service = acrServiceName
	}
	token, expiresIn, err := h.mintRegistryToken(p, service, scope)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"access_token": token,
		"expires_in":   expiresIn,
		"issued_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *Handler) mintRegistryToken(p authn.Principal, service, scope string) (string, int, error) {
	const expiresIn = 3600
	exp := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
	kid, priv, err := h.Store.EnsureEntraSigningKey()
	if err != nil {
		return "", 0, err
	}
	aud := service
	if aud == acrServiceName {
		aud = authn.AudienceACR
	}
	claims := map[string]any{
		"aud":   aud,
		"iss":   "http://127.0.0.1:4599/oauth2/token",
		"iat":   time.Now().UTC().Unix(),
		"nbf":   time.Now().UTC().Unix(),
		"exp":   exp.Unix(),
		"sub":   p.ID,
		"oid":   p.ID,
		"scope": scope,
	}
	token, err := authn.EncodeRS256JWT(priv, kid, claims)
	if err != nil {
		return "", 0, err
	}
	if err := h.Store.PutAccessToken(authn.HashToken(token), p.ID, exp); err != nil {
		return "", 0, err
	}
	return token, expiresIn, nil
}

func (h *Handler) requireV2(w http.ResponseWriter, r *http.Request, repo string, push bool) bool {
	p, err := h.authenticateRegistry(r)
	if err != nil {
		scope := ""
		if repo != "" {
			action := "pull"
			if push {
				action = "push,pull"
			}
			scope = "repository:" + sanitizeScopeName(repo) + ":" + action
		}
		writeRegistryUnauthorized(w, r, scope)
		return false
	}
	if !p.AllowsRegistry() {
		writeRegistryError(w, http.StatusForbidden, "DENIED", "token audience is not allowed for registry")
		return false
	}
	if p.IsRoot || h.principalIsRoot(p) {
		return true
	}
	if h.Authz == nil {
		writeRegistryError(w, http.StatusForbidden, "DENIED", "access denied")
		return false
	}
	scope := h.registryAuthzScope(r)
	actions := []string{
		"Microsoft.ContainerRegistry/registries/pull/read",
		"Microsoft.ContainerRegistry/registries/read",
	}
	if push {
		actions = []string{
			"Microsoft.ContainerRegistry/registries/push/write",
			"Microsoft.ContainerRegistry/registries/write",
		}
	}
	for _, action := range actions {
		ok, err := h.Authz.Evaluate(p.ID, p.IsRoot, action, scope)
		if err != nil {
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
			return false
		}
		if ok {
			return true
		}
	}
	writeRegistryError(w, http.StatusForbidden, "DENIED", "access denied")
	return false
}

func (h *Handler) principalIsRoot(p authn.Principal) bool {
	if h == nil || h.Auth == nil || p.ID == "" {
		return false
	}
	rootID := h.Auth.RootClientID
	if rootID == "" {
		rootID = "root"
	}
	return p.ID == rootID
}

func (h *Handler) registryAuthzScope(r *http.Request) string {
	name := registryNameFromRequest(r)
	if name != "" && h.Store != nil {
		row, ok, err := h.Store.GetProviderResourceByName(providerKey, name)
		if err == nil && ok {
			return "/subscriptions/" + row.SubscriptionID + "/resourceGroups/" + row.ResourceGroup +
				"/providers/Microsoft.ContainerRegistry/registries/" + row.Name
		}
	}
	return "/subscriptions/" + h.defaultSubscription()
}

func (h *Handler) authenticateRegistry(r *http.Request) (authn.Principal, error) {
	if h.Auth == nil {
		return authn.Principal{}, authn.ErrUnauthenticated
	}
	p, err := h.Auth.AuthenticateRequest(r)
	if err == nil {
		return p, nil
	}
	_, pass, ok := parseBasic(r.Header.Get("Authorization"))
	if !ok || pass == "" {
		return authn.Principal{}, authn.ErrUnauthenticated
	}
	return h.Auth.AuthenticateToken(pass)
}

func registryNameFromRequest(r *http.Request) string {
	host := r.Host
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, suffix := range []string{".azurecr.io", ".containerregistry.azure.net"} {
		if strings.HasSuffix(host, suffix) {
			return strings.TrimSuffix(host, suffix)
		}
	}
	_, name, extra := parseRegistryV2Path(r.URL.Path)
	if name == "" {
		name = extra
	}
	if name != "" {
		if i := strings.IndexByte(name, '/'); i > 0 {
			return name[:i]
		}
		return name
	}
	return ""
}

func writeRegistryUnauthorized(w http.ResponseWriter, r *http.Request, scope string) {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "127.0.0.1:4599"
	}
	realm := "http://" + host + "/oauth2/token"
	wa := `Bearer realm="` + realm + `",service="` + acrServiceName + `"`
	if scope != "" {
		wa += `,scope="` + scope + `"`
	}
	w.Header().Set(distributionAPIHeader, distributionAPIVersion)
	w.Header().Set("WWW-Authenticate", wa)
	writeRegistryError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
}

func writeRegistryError(w http.ResponseWriter, code int, errCode, message string) {
	if w.Header().Get(distributionAPIHeader) == "" {
		w.Header().Set(distributionAPIHeader, distributionAPIVersion)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]any{{"code": errCode, "message": message}},
	})
}

func parseBasic(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func sha256Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(d string) bool {
	d = strings.TrimSpace(d)
	const prefix = "sha256:"
	if !strings.HasPrefix(d, prefix) {
		return false
	}
	hexPart := d[len(prefix):]
	if len(hexPart) != 64 {
		return false
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validRepoName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '/' || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	return true
}

func sanitizeScopeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '/' || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
