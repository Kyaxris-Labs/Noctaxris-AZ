// Package azauth provides shared ARM and data-plane Bearer gates.
package azauth

import (
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
)

// AudienceOK reports whether a principal may call a data-plane resource.
type AudienceOK func(authn.Principal) bool

// RequireDataPlaneBearer authenticates Authorization Bearer, checks resource
// audience, then evaluates Azure RBAC for action at scope. Root skips audience
// and Authz (same as Principal.Allows* and Evaluator.Evaluate). Writes ARM-shaped
// 401 / InvalidAuthenticationTokenAudience / 403 on failure.
func RequireDataPlaneBearer(
	w http.ResponseWriter,
	r *http.Request,
	auth *authn.Authenticator,
	ev *authz.Evaluator,
	allows AudienceOK,
	action, scope string,
) (authn.Principal, bool) {
	if auth == nil {
		azerrors.Unauthenticated(w, "")
		return authn.Principal{}, false
	}
	p, err := auth.AuthenticateRequest(r)
	if err != nil {
		azerrors.Unauthenticated(w, "")
		return authn.Principal{}, false
	}
	if allows == nil || !allows(p) {
		azerrors.InvalidAuthenticationTokenAudience(w, "")
		return authn.Principal{}, false
	}
	if p.IsRoot {
		return p, true
	}
	if action == "" || scope == "" {
		azerrors.Forbidden(w, "")
		return authn.Principal{}, false
	}
	if ev == nil {
		azerrors.Forbidden(w, "")
		return authn.Principal{}, false
	}
	ok, err := ev.Evaluate(p.ID, p.IsRoot, action, scope)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return authn.Principal{}, false
	}
	if !ok {
		azerrors.Forbidden(w, "")
		return authn.Principal{}, false
	}
	return p, true
}

// RequireARMBearer is the control-plane gate (ARM audience + RBAC).
func RequireARMBearer(
	w http.ResponseWriter,
	r *http.Request,
	auth *authn.Authenticator,
	ev *authz.Evaluator,
	action, scope string,
) (authn.Principal, bool) {
	return RequireDataPlaneBearer(w, r, auth, ev, authn.Principal.AllowsARM, action, scope)
}
