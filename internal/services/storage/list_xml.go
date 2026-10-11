package storage

import (
	"encoding/xml"
	"net/http"
	"strings"
)

// wantsAzureListXML reports Azure CLI / SDK list shapes.
// Bare ?comp=list without restype keeps JSON for lab curl / challenge parsers.
func wantsAzureListXML(r *http.Request) bool {
	if r == nil {
		return false
	}
	q := r.URL.Query()
	restype := strings.ToLower(strings.TrimSpace(q.Get("restype")))
	comp := strings.ToLower(strings.TrimSpace(q.Get("comp")))
	if comp == "list" && (restype == "container" || restype == "service") {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/xml") || strings.Contains(accept, "text/xml") {
		return true
	}
	return false
}

func serviceEndpoint(r *http.Request) string {
	if r == nil {
		return "http://127.0.0.1:4599/"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "127.0.0.1:4599"
	}
	return scheme + "://" + host + "/"
}

func writeBlobEnumerationXML(w http.ResponseWriter, endpoint, container string, names []string) {
	type props struct {
		ContentLength int `xml:"Content-Length"`
	}
	type blob struct {
		Name       string `xml:"Name"`
		Properties props  `xml:"Properties"`
	}
	type blobs struct {
		Blob []blob `xml:"Blob"`
	}
	type results struct {
		XMLName       xml.Name `xml:"EnumerationResults"`
		ServiceEP     string   `xml:"ServiceEndpoint,attr"`
		ContainerName string   `xml:"ContainerName,attr"`
		Blobs         blobs    `xml:"Blobs"`
		NextMarker    string   `xml:"NextMarker"`
	}
	out := results{
		ServiceEP:     endpoint,
		ContainerName: container,
		NextMarker:    "",
	}
	for _, name := range names {
		out.Blobs.Blob = append(out.Blobs.Blob, blob{Name: name, Properties: props{ContentLength: 0}})
	}
	writeXML(w, http.StatusOK, out)
}

func writeContainerEnumerationXML(w http.ResponseWriter, endpoint, account string, names []string) {
	type container struct {
		Name string `xml:"Name"`
	}
	type containers struct {
		Container []container `xml:"Container"`
	}
	type results struct {
		XMLName    xml.Name   `xml:"EnumerationResults"`
		ServiceEP  string     `xml:"ServiceEndpoint,attr"`
		Prefix     string     `xml:"Prefix,attr"`
		Containers containers `xml:"Containers"`
		NextMarker string     `xml:"NextMarker"`
	}
	_ = account
	out := results{ServiceEP: endpoint, NextMarker: ""}
	for _, name := range names {
		out.Containers.Container = append(out.Containers.Container, container{Name: name})
	}
	writeXML(w, http.StatusOK, out)
}

func writeXML(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	_ = enc.Encode(v)
}
