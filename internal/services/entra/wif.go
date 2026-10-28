package entra

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func (s *Service) entraIssuer() string {
	return s.entraIssuerAt(s.base())
}

func (s *Service) entraIssuerAt(origin string) string {
	return strings.TrimRight(strings.TrimSpace(origin), "/") + "/" + s.appTenant() + "/v2.0"
}

func (s *Service) labOIDCIssuer() string {
	return s.labOIDCIssuerAt(s.base())
}

func (s *Service) labOIDCIssuerAt(origin string) string {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		origin = s.base()
	}
	pref := "/_noctaxris-az/oidc-lab"
	if s.StripProduct {
		pref = "/_lab/oidc-lab"
	}
	return origin + pref
}

func (s *Service) isLabOIDCIssuer(iss string) bool {
	_, ok := config.LabOIDCIssuerPath(iss)
	return ok
}

func (s *Service) isEntraIssuedAssertion(iss string, r *http.Request) bool {
	iss = strings.TrimSpace(iss)
	if iss == "" {
		return false
	}
	seen := map[string]struct{}{}
	for _, base := range []string{s.base(), s.origin(r)} {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}
		if _, ok := seen[base]; ok {
			continue
		}
		seen[base] = struct{}{}
		prefix := base + "/" + s.appTenant()
		if iss == prefix+"/v2.0" || strings.HasPrefix(iss, prefix) {
			return true
		}
	}
	return false
}

func (s *Service) verifyClientAssertion(w http.ResponseWriter, r *http.Request, clientID, assertion string) (string, bool) {
	_, claims, err := authn.DecodeJWTUnverified(assertion)
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "client_assertion is not a JWT")
		return "", false
	}
	iss := authn.ClaimString(claims, "iss")
	sub := authn.ClaimString(claims, "sub")
	aud := authn.ClaimString(claims, "aud")
	if s.isEntraIssuedAssertion(iss, r) {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "Entra-issued tokens cannot be used as federated assertions")
		return "", false
	}

	if s.isLabOIDCIssuer(iss) {
		return s.verifyFederatedAssertion(w, r, clientID, assertion, iss, aud)
	}
	return s.verifyPrivateKeyJWT(w, r, clientID, assertion, iss, sub, aud)
}

func (s *Service) verifyFederatedAssertion(w http.ResponseWriter, r *http.Request, clientID, assertion, iss, aud string) (string, bool) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "client_id is required for federated client_assertion")
		return "", false
	}
	_, priv, err := s.ensureOIDCLabKey()
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return "", false
	}
	claims, err := authn.VerifyRS256JWT(&priv.PublicKey, assertion, s.now())
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "federated assertion signature is invalid")
		return "", false
	}
	appIDs := s.federatedMatchAppIDs(clientID)
	if len(appIDs) == 0 {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "client_id is required for federated client_assertion")
		return "", false
	}
	fic, ok, err := s.Store.MatchFIC(iss, aud, claims, appIDs...)
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return "", false
	}
	if !ok {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "federated credential subject/issuer/audience did not match")
		return "", false
	}
	_, appID, _, found, err := s.Store.ResolveEntraApp(s.appTenant(), fic.AppObjectID)
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return "", false
	}
	if found && clientID != appID && clientID != fic.AppObjectID {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "client_id does not match federated credential application")
		return "", false
	}
	if found {
		return appID, true
	}
	return clientID, true
}

func (s *Service) federatedMatchAppIDs(clientID string) []string {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil
	}
	ids := []string{clientID}
	if obj, appID, _, ok, err := s.Store.ResolveEntraApp(s.appTenant(), clientID); err == nil && ok {
		ids = append(ids, obj, appID)
	}
	if sp, ok, err := s.Store.GetServicePrincipal(clientID); err == nil && ok {
		ids = append(ids, sp.ID, sp.AppID)
		if obj, appID, _, found, err := s.Store.ResolveEntraApp(s.appTenant(), sp.AppID); err == nil && found {
			ids = append(ids, obj, appID)
		}
	}
	return ids
}

func (s *Service) assertionAudOK(r *http.Request, aud string) bool {
	aud = strings.TrimSpace(aud)
	if aud == "" {
		return false
	}
	seen := map[string]struct{}{}
	tenant := s.pathTenant(r)
	for _, base := range []string{s.origin(r), s.base()} {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}
		if _, ok := seen[base]; ok {
			continue
		}
		seen[base] = struct{}{}
		candidates := []string{
			base + "/" + tenant + "/oauth2/v2.0/token",
			base + "/" + tenant + "/oauth2/token",
			base + "/" + s.appTenant() + "/oauth2/v2.0/token",
		}
		for _, c := range candidates {
			if aud == c {
				return true
			}
		}
	}
	return false
}

func (s *Service) verifyPrivateKeyJWT(w http.ResponseWriter, r *http.Request, clientID, assertion, iss, sub, aud string) (string, bool) {
	if clientID == "" {
		clientID = iss
	}
	if iss == "" || sub == "" || iss != sub {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "private_key_jwt iss and sub must equal the application client id")
		return "", false
	}
	if clientID != iss {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "client_id does not match assertion iss")
		return "", false
	}
	if !s.assertionAudOK(r, aud) {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "assertion aud must be the token endpoint")
		return "", false
	}
	objID, appID, _, ok, err := s.Store.ResolveEntraApp(s.appTenant(), clientID)
	if err != nil || !ok {
		azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "application not found for certificate assertion")
		return "", false
	}
	pems, err := s.Store.ListKeyPEMs(objID)
	if err != nil {
		azerrors.WriteOAuth(w, http.StatusInternalServerError, "server_error", err.Error())
		return "", false
	}
	if len(pems) == 0 {
		sp, spOK, _ := s.Store.GetServicePrincipal(clientID)
		if spOK {
			pems, _ = s.Store.ListKeyPEMs(sp.ID)
		}
	}
	for _, pemBytes := range pems {
		pub, perr := parseRSAPublicPEM([]byte(pemBytes))
		if perr != nil {
			continue
		}
		if _, err := authn.VerifyRS256JWT(pub, assertion, s.now()); err == nil {
			return appID, true
		}
	}
	azerrors.WriteOAuth(w, http.StatusUnauthorized, "invalid_client", "client_assertion was not signed by a registered key credential")
	return "", false
}

func parseRSAPublicPEM(raw []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errPEM
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errPEM
		}
		return pub, nil
	}
	if pk, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		pub, ok := pk.(*rsa.PublicKey)
		if !ok {
			return nil, errPEM
		}
		return pub, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &key.PublicKey, nil
	}
	if pk, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, ok := pk.(*rsa.PrivateKey)
		if !ok {
			return nil, errPEM
		}
		return &key.PublicKey, nil
	}
	return nil, errPEM
}

var errPEM = errString("unsupported public key PEM")

type errString string

func (e errString) Error() string { return string(e) }
