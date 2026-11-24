// Package netutil holds small network and text helpers shared by scanners and the UI.
package netutil

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrNotPrivate = errors.New("only private ranges (10/8, 172.16/12, 192.168/16) can be scanned")
	ErrTooLarge   = errors.New("range too large: the prefix must be /22 or smaller (at most 1024 addresses)")
)

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// ValidateScanCIDR parses s and checks it is a private IPv4 range of /22 or smaller.
func ValidateScanCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, errors.New("only IPv4 ranges are supported")
	}
	p = p.Masked()
	private := false
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			private = true
		}
	}
	if !private {
		return netip.Prefix{}, ErrNotPrivate
	}
	if p.Bits() < 22 {
		return netip.Prefix{}, ErrTooLarge
	}
	return p, nil
}

// Hosts lists the usable addresses in p (network and broadcast excluded for /30 and larger).
func Hosts(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	var out []netip.Addr
	for a := p.Addr(); p.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	if p.Bits() <= 30 && len(out) >= 2 {
		out = out[1 : len(out)-1]
	}
	return out
}

// NormalizeMAC returns mac in upper-case colon form.
func NormalizeMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.ReplaceAll(strings.TrimSpace(s), "-", ":"))
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC %q", s)
	}
	return strings.ToUpper(hw.String()), nil
}

// IsLocallyAdministered reports whether the MAC has the locally-administered
// bit set, which phones use for randomized addresses.
func IsLocallyAdministered(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b, err := hex.DecodeString(mac[:2])
	if err != nil {
		return false
	}
	return b[0]&0x02 != 0
}

// ARPEntry is one row of /proc/net/arp.
type ARPEntry struct {
	IP    netip.Addr
	MAC   string
	Iface string
}

// ParseProcARP parses /proc/net/arp, skipping incomplete entries.
func ParseProcARP(r io.Reader) ([]ARPEntry, error) {
	var out []ARPEntry
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 || f[2] == "0x0" || f[3] == "00:00:00:00:00:00" {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		mac, err := NormalizeMAC(f[3])
		if err != nil {
			continue
		}
		out = append(out, ARPEntry{IP: ip, MAC: mac, Iface: f[5]})
	}
	return out, sc.Err()
}

// ParseProcRoute returns the interface and gateway of the IPv4 default route.
func ParseProcRoute(r io.Reader) (string, netip.Addr, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(f[2])
		if err != nil || len(b) != 4 {
			continue
		}
		var a [4]byte
		binary.LittleEndian.PutUint32(a[:], binary.BigEndian.Uint32(b))
		return f[0], netip.AddrFrom4(a), nil
	}
	if err := sc.Err(); err != nil {
		return "", netip.Addr{}, err
	}
	return "", netip.Addr{}, errors.New("no default route")
}

// CleanText drops control characters, trims space and limits s to max runes.
func CleanText(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}
