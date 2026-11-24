package tlsutil

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCreateThenLoad(t *testing.T) {
	dir := t.TempDir()
	now := func() time.Time { return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) }
	c1, err := LoadOrCreate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := LoadOrCreate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Fatal("certificate regenerated")
	}
	leaf, err := x509.ParseCertificate(c1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.Before(now().Add(9*365*24*time.Hour)) || !containsName(leaf.DNSNames, "localhost") {
		t.Fatalf("leaf %v %v", leaf.NotAfter, leaf.DNSNames)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "honet-key.pem"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("key perms %v", fi.Mode())
		}
	}
}

func TestInsaneClock(t *testing.T) {
	c, err := LoadOrCreate(t.TempDir(), func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	if leaf.NotBefore.Year() != 2025 || leaf.NotAfter.Year() < 2034 {
		t.Fatalf("%v - %v", leaf.NotBefore, leaf.NotAfter)
	}
}

func containsName(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
