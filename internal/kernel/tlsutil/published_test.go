package tlsutil

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPublishedCertAddsRequestIP(t *testing.T) {
	dir := t.TempDir()
	paths, err := EnsureListenCert(dir, time.Now().UTC().Add(time.Hour), "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if paths.CAKey != filepath.Join(dir, "lab-ca.key") {
		t.Fatalf("ca key path %s", paths.CAKey)
	}
	pc, err := OpenPublishedCerts(paths)
	if err != nil || pc == nil {
		t.Fatalf("open: %v %v", pc, err)
	}
	pc.Note("login.microsoftonline.com:443")
	pc.Note("127.0.0.1:4599")
	cert, err := pc.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !hasIP(leaf, "203.0.113.10") {
		t.Fatalf("pinned public ip missing: %v", leaf.IPAddresses)
	}
	if !hasIP(leaf, "127.0.0.1") {
		t.Fatal("loopback ip missing from initial leaf")
	}
	for _, name := range leaf.DNSNames {
		if name == "login.microsoftonline.com" {
			t.Fatal("dns host from a request must not be signed")
		}
	}

	pc.Note("198.51.100.20:59991")
	cert, err = pc.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !hasIP(leaf, "198.51.100.20") || !hasIP(leaf, "203.0.113.10") || !hasIP(leaf, "127.0.0.1") {
		t.Fatalf("ips after note: %v", leaf.IPAddresses)
	}
}

func TestPublishedCertSecondHandshakeMatchesDialedIP(t *testing.T) {
	ip := firstNonLoopbackIPv4()
	if ip == "" {
		t.Skip("no non-loopback ipv4")
	}
	dir := t.TempDir()
	paths, err := EnsureListenCert(dir, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := OpenPublishedCerts(paths)
	if err != nil || pc == nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(paths.CACert)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca pool")
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: pc.GetCertificate,
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pc.Note(r.Host)
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(tlsLn) }()
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	skip := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	if err := httpGet(addr, skip); err != nil {
		t.Fatal(err)
	}
	if err := httpGet(addr, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatalf("verified dial to %s: %v", addr, err)
	}
}

func hasIP(leaf *x509.Certificate, want string) bool {
	target := net.ParseIP(want)
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}

func firstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP.To4()
			case *net.IPAddr:
				ip = v.IP.To4()
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

func httpGet(addr string, cfg *tls.Config) error {
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		return err
	}
	if err := req.Write(conn); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}
