package aks

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/azauth"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
)

const providerKey = "Microsoft.ContainerService/managedClusters"
const armType = "Microsoft.ContainerService/managedClusters"

const (
	actionListAdminCred = "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
	actionListUserCred  = "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"
)

// Handler serves Microsoft.ContainerService/managedClusters ARM lite.
type Handler struct {
	Store *store.Store
	Auth  *authn.Authenticator
	Authz *authz.Evaluator
}

// Register mounts routes.
func (h *Handler) Register(mux *http.ServeMux) {
	base := "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ContainerService/managedClusters"
	mux.HandleFunc("PUT "+base+"/{name}", h.put)
	mux.HandleFunc("GET "+base+"/{name}", h.get)
	mux.HandleFunc("DELETE "+base+"/{name}", h.del)
	mux.HandleFunc("GET "+base, h.list)
	mux.HandleFunc("POST "+base+"/{name}/listClusterAdminCredential", h.listAdminCredential)
	mux.HandleFunc("POST "+base+"/{name}/listClusterUserCredential", h.listUserCredential)
}

func theatreKubeconfig(name string) string {
	return "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n  name: " + name + "\ncontexts:\n- context:\n    cluster: " + name + "\n    user: lab\n  name: " + name + "\ncurrent-context: " + name + "\nusers:\n- name: lab\n  user:\n    token: noctaxris-az-aks-theatre\n"
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.ContainerService/managedClusters/write") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	location := "eastus"
	props := map[string]any{
		"provisioningState": "Succeeded",
		"powerState":        map[string]any{"code": "Running"},
		"kubernetesVersion": "1.29.0",
		"fqdn":              name + ".lab.noctaxris-az.local",
	}
	props["kubeConfig"] = theatreKubeconfig(name)
	var body struct {
		Location   string         `json:"location"`
		Properties map[string]any `json:"properties"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if body.Location != "" {
		location = body.Location
	}
	if body.Properties != nil {
		for k, v := range body.Properties {
			props[k] = v
		}
	}
	b, _ := json.Marshal(props)
	if err := h.Store.UpsertProviderResource(providerKey, sub, rg, name, location, string(b)); err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resourceJSON(sub, rg, name, location, publicProps(props)))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.ContainerService/managedClusters/read") {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	row, ok, err := h.Store.GetProviderResource(providerKey, sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "resource not found")
		return
	}
	var props map[string]any
	_ = json.Unmarshal([]byte(row.PropertiesJSON), &props)
	if props == nil {
		props = map[string]any{"provisioningState": "Succeeded"}
	}
	writeJSON(w, http.StatusOK, resourceJSON(sub, rg, name, row.Location, publicProps(props)))
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.ContainerService/managedClusters/delete") {
		return
	}
	err := h.Store.DeleteProviderResource(providerKey, r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name"))
	if err == sql.ErrNoRows {
		azerrors.NotFound(w, "resource not found")
		return
	}
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if !h.require(w, r, "Microsoft.ContainerService/managedClusters/read") {
		return
	}
	rows, err := h.Store.ListProviderResources(providerKey, r.PathValue("sub"), r.PathValue("rg"))
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	value := make([]any, 0, len(rows))
	for _, row := range rows {
		var props map[string]any
		_ = json.Unmarshal([]byte(row.PropertiesJSON), &props)
		value = append(value, resourceJSON(row.SubscriptionID, row.ResourceGroup, row.Name, row.Location, publicProps(props)))
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

func (h *Handler) listAdminCredential(w http.ResponseWriter, r *http.Request) {
	h.listCredential(w, r, actionListAdminCred)
}

func (h *Handler) listUserCredential(w http.ResponseWriter, r *http.Request) {
	h.listCredential(w, r, actionListUserCred)
}

func (h *Handler) listCredential(w http.ResponseWriter, r *http.Request, action string) {
	if !h.require(w, r, action) {
		return
	}
	sub, rg, name := r.PathValue("sub"), r.PathValue("rg"), r.PathValue("name")
	row, ok, err := h.Store.GetProviderResource(providerKey, sub, rg, name)
	if err != nil {
		azerrors.WriteARM(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	if !ok {
		azerrors.NotFound(w, "resource not found")
		return
	}
	var props map[string]any
	_ = json.Unmarshal([]byte(row.PropertiesJSON), &props)
	kube, _ := props["kubeConfig"].(string)
	if kube == "" {
		kube = theatreKubeconfig(name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"kubeconfigs": []map[string]any{{
			"name":  "clusterAdmin",
			"value": kube,
		}},
	})
}

func publicProps(props map[string]any) map[string]any {
	if props == nil {
		return map[string]any{"provisioningState": "Succeeded"}
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		if k == "kubeConfig" || k == "kubeconfig" {
			continue
		}
		out[k] = v
	}
	return out
}

func resourceJSON(sub, rg, name, location string, props map[string]any) map[string]any {
	id := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.ContainerService/managedClusters/" + name
	return map[string]any{
		"id": id, "name": name, "type": armType, "location": location, "properties": props,
	}
}

func (h *Handler) require(w http.ResponseWriter, r *http.Request, action string) bool {
	scope := "/subscriptions/" + r.PathValue("sub") + "/resourceGroups/" + r.PathValue("rg")
	_, ok := azauth.RequireARMBearer(w, r, h.Auth, h.Authz, action, scope)
	return ok
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
