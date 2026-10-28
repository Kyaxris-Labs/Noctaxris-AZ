package tlsutil

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const maxPublishedIPs = 16

// PublishedCerts is the TLS-auto leaf. It always names loopback. After a
// request arrives with an IP Host, later handshakes also name that IP.
// DNS names from the Host are ignored so the lab CA is not used to sign
// arbitrary hostnames.
type PublishedCerts struct {
	mu       sync.Mutex
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	srvKey   *ecdsa.PrivateKey
	notAfter time.Time
	seen     map[string]net.IP
	current  *tls.Certificate
}

// OpenPublishedCerts loads the TLS-auto CA key and server key.
// A missing CA key returns (nil, nil) so callers keep the static leaf.
func OpenPublishedCerts(p Paths) (*PublishedCerts, error) {
	if p.CAKey == "" || p.CACert == "" || p.ServerKey == "" || p.ServerCert == "" {
		return nil, nil
	}
	if !fileExists(p.CAKey) {
		return nil, nil
	}
	ca, err := readCert(p.CACert)
	if err != nil {
		return nil, err
	}
	caKey, err := readECKey(p.CAKey)
	if err != nil {
		return nil, err
	}
	srvKey, err := readECKey(p.ServerKey)
	if err != nil {
		return nil, err
	}
	leaf, err := tls.LoadX509KeyPair(p.ServerCert, p.ServerKey)
	if err != nil {
		return nil, err
	}
	notAfter := time.Now().UTC().Add(365 * 24 * time.Hour)
	seen := map[string]net.IP{}
	if parsed, err := x509.ParseCertificate(leaf.Certificate[0]); err == nil {
		notAfter = parsed.NotAfter
		for _, ip := range parsed.IPAddresses {
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			seen[ip.String()] = ip
		}
	}
	return &PublishedCerts{
		ca:       ca,
		caKey:    caKey,
		srvKey:   srvKey,
		notAfter: notAfter,
		seen:     seen,
		current:  &leaf,
	}, nil
}

// Note records an IP from a request Host (host or host:port).
func (p *PublishedCerts) Note(hostport string) {
	if p == nil {
		return
	}
	ip := hostIP(hostport)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return
	}
	key := ip.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[key]; ok {
		return
	}
	if len(p.seen) >= maxPublishedIPs {
		return
	}
	p.seen[key] = ip
	if err := p.rebuildLocked(); err != nil {
		delete(p.seen, key)
	}
}

// GetCertificate returns the current leaf.
func (p *PublishedCerts) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p == nil {
		return nil, errors.New("no certificate")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current == nil {
		return nil, errors.New("no certificate")
	}
	c := *p.current
	return &c, nil
}

func (p *PublishedCerts) rebuildLocked() error {
	serial, err := randSerial()
	if err != nil {
		return err
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, ip := range p.seen {
		ips = append(ips, ip)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().UTC().Add(-time.Hour),
		NotAfter:     p.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &p.srvKey.PublicKey, p.caKey)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	p.current = &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  p.srvKey,
		Leaf:        leaf,
	}
	return nil
}

func hostIP(hostport string) net.IP {
	host := strings.TrimSpace(hostport)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return net.ParseIP(host)
}

func readCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("ca pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readECKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("key pem")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
