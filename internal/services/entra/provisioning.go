package entra

import (
	"encoding/xml"
	"io"
	"net/http"
	"strings"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
)

func (s *Service) mountProvisioningSOAP(mux *http.ServeMux) {
	mux.HandleFunc("POST /provisioningwebservice.svc", s.handleProvisioningSOAP)
}

func (s *Service) handleProvisioningSOAP(w http.ResponseWriter, r *http.Request) {
	if _, ok := authn.PrincipalFromContext(r.Context()); !ok {
		if authn.IsPublicPath(r.URL.Path) {
			// SOAP is public-path classified so AADInternals can post; still accept Bearer when present.
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		azerrors.BadRequest(w, "unable to read SOAP body")
		return
	}
	raw := string(body)
	if strings.Contains(raw, "ListUsers") || strings.Contains(strings.ToLower(raw), "listusers") {
		s.writeSOAPListUsers(w)
		return
	}
	s.writeSOAPTenant(w)
}

func (s *Service) writeSOAPListUsers(w http.ResponseWriter) {
	users, err := s.Store.ListDirectoryUsers(s.appTenant())
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><ListUsersResponse xmlns="http://provisioning.microsoftonline.com/">`)
	for _, u := range users {
		b.WriteString("<User><UserPrincipalName>")
		b.WriteString(xmlEscape(u.UserPrincipalName))
		b.WriteString("</UserPrincipalName><DisplayName>")
		b.WriteString(xmlEscape(u.DisplayName))
		b.WriteString("</DisplayName><ObjectId>")
		b.WriteString(xmlEscape(u.ID))
		b.WriteString("</ObjectId></User>")
	}
	b.WriteString(`</ListUsersResponse></s:Body></s:Envelope>`)
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *Service) writeSOAPTenant(w http.ResponseWriter) {
	body := `<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><CompanyResponse xmlns="http://provisioning.microsoftonline.com/"><DisplayName>Noctaxris-AZ Lab</DisplayName><ContextId>` +
		xmlEscape(s.appTenant()) + `</ContextId></CompanyResponse></s:Body></s:Envelope>`
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
