// Package tlsutil creates and loads honet's self-signed certificate.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// LoadOrCreate loads honet-cert.pem/honet-key.pem from dir, creating a
// self-signed ECDSA P-256 certificate valid for 10 years if they are missing.
func LoadOrCreate(dir string, now func() time.Time) (tls.Certificate, error) {
	certPath := filepath.Join(dir, "honet-cert.pem")
	keyPath := filepath.Join(dir, "honet-key.pem")
	if _, err := os.Stat(certPath); err == nil {
		return tls.LoadX509KeyPair(certPath, keyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	start := now().Add(-time.Hour)
	if start.Year() < 2025 { // no RTC on the Pi: avoid a "not yet valid" cert
		start = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	host, _ := os.Hostname()
	names := []string{"localhost"}
	if host != "" {
		names = append(names, host, host+".local")
	}
	ips := []net.IP{net.IPv4(127, 0, 0, 1)}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				ips = append(ips, n.IP.To4())
			}
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "honet", Organization: []string{"Honet (self-signed)"}},
		NotBefore:             start,
		NotAfter:              start.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
