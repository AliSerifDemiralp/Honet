package netutil

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValidateScanCIDR(t *testing.T) {
	ok := map[string]string{
		"192.168.1.0/24":  "192.168.1.0/24",
		"192.168.1.77/24": "192.168.1.0/24",
		"10.0.0.0/22":     "10.0.0.0/22",
		"172.16.5.0/24":   "172.16.5.0/24",
	}
	for in, want := range ok {
		p, err := ValidateScanCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("%s: %v %v", in, p, err)
		}
	}
	if _, err := ValidateScanCIDR("10.0.0.0/21"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("/21: %v", err)
	}
	for _, in := range []string{"8.8.8.0/24", "172.32.0.0/24"} {
		if _, err := ValidateScanCIDR(in); !errors.Is(err, ErrNotPrivate) {
			t.Errorf("%s: %v", in, err)
		}
	}
	for _, in := range []string{"--script=x", "fd00::/64", "", "192.168.1.0"} {
		if _, err := ValidateScanCIDR(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestHosts(t *testing.T) {
	h := Hosts(netip.MustParsePrefix("192.168.1.0/24"))
	if len(h) != 254 || h[0].String() != "192.168.1.1" || h[253].String() != "192.168.1.254" {
		t.Fatalf("len %d first %v last %v", len(h), h[0], h[len(h)-1])
	}
	if n := len(Hosts(netip.MustParsePrefix("10.0.0.0/31"))); n != 2 {
		t.Fatalf("/31 -> %d", n)
	}
}

func TestMAC(t *testing.T) {
	m, err := NormalizeMAC("aa-bb-cc-dd-ee-0f")
	if err != nil || m != "AA:BB:CC:DD:EE:0F" {
		t.Fatalf("%q %v", m, err)
	}
	if _, err := NormalizeMAC("zz"); err == nil {
		t.Fatal("bad mac accepted")
	}
	if !IsLocallyAdministered("DA:A1:19:00:00:01") || IsLocallyAdministered("B8:27:EB:00:00:01") || IsLocallyAdministered("") {
		t.Fatal("locally administered bit")
	}
}

const procARP = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:00:00:01     *        wlan0
192.168.1.20     0x1         0x2         aa:bb:cc:00:00:14     *        wlan0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlan0
`

func TestParseProcARP(t *testing.T) {
	e, err := ParseProcARP(strings.NewReader(procARP))
	if err != nil || len(e) != 2 {
		t.Fatalf("%v %v", e, err)
	}
	if e[1].IP.String() != "192.168.1.20" || e[1].MAC != "AA:BB:CC:00:00:14" || e[1].Iface != "wlan0" {
		t.Fatalf("%+v", e[1])
	}
}

const procRoute = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"wlan0\t0001A8C0\t00000000\t0001\t0\t0\t303\t00FFFFFF\t0\t0\t0\n" +
	"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t303\t00000000\t0\t0\t0\n"

func TestParseProcRoute(t *testing.T) {
	iface, gw, err := ParseProcRoute(strings.NewReader(procRoute))
	if err != nil || iface != "wlan0" || gw.String() != "192.168.1.1" {
		t.Fatalf("%q %v %v", iface, gw, err)
	}
	if _, _, err := ParseProcRoute(strings.NewReader("Iface\tDestination\n")); err == nil {
		t.Fatal("no default route should error")
	}
}

func TestCleanText(t *testing.T) {
	if got := CleanText("<b>\x00tv\n</b>", 64); got != "<b>tv</b>" {
		t.Fatalf("%q", got)
	}
	long := strings.Repeat("ş", 500)
	if got := CleanText(long, 64); utf8.RuneCountInString(got) != 64 || !utf8.ValidString(got) {
		t.Fatalf("len %d", utf8.RuneCountInString(got))
	}
	if got := CleanText("  a b  ", 10); got != "a b" {
		t.Fatalf("%q", got)
	}
}
