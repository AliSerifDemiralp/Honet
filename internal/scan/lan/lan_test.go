package lan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/AliSerifDemiralp/honet/internal/netutil"
)

func listenPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := net.SplitHostPort(l.Addr().String())
	n, _ := strconv.Atoi(p)
	return l, n
}

func TestTCPProber(t *testing.T) {
	l1, open1 := listenPort(t)
	defer l1.Close()
	l2, open2 := listenPort(t)
	defer l2.Close()
	l3, closed := listenPort(t)
	l3.Close()
	pr := TCPProber{Concurrency: 32, Timeout: 800 * time.Millisecond}
	got, err := pr.Probe(context.Background(), netip.MustParseAddr("127.0.0.1"), []int{open2, closed, open1})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{open1, open2}
	if open2 < open1 {
		want = []int{open2, open1}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTCPProberCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pr := TCPProber{Concurrency: 4, Timeout: time.Second}
	if _, err := pr.Probe(ctx, netip.MustParseAddr("127.0.0.1"), CommonPorts); err != nil {
		t.Fatalf("cancelled probe should not error: %v", err)
	}
}

func TestCommonPortsCount(t *testing.T) {
	seen := map[int]bool{}
	for _, p := range CommonPorts {
		if seen[p] {
			t.Fatalf("duplicate %d", p)
		}
		seen[p] = true
	}
	if len(CommonPorts) != 57 {
		t.Fatalf("len %d", len(CommonPorts))
	}
}

type fakeResolver struct {
	names []string
	err   error
}

func (f fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return f.names, f.err
}

func TestReverseName(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.20")
	if got := ReverseName(context.Background(), fakeResolver{names: []string{"<script>tv.lan.\x07"}}, ip, time.Second); got != "<script>tv.lan" {
		t.Fatalf("%q", got)
	}
	if got := ReverseName(context.Background(), fakeResolver{err: errors.New("nx")}, ip, time.Second); got != "" {
		t.Fatalf("%q", got)
	}
	long := strings.Repeat("a", 600) + "."
	if got := ReverseName(context.Background(), fakeResolver{names: []string{long}}, ip, time.Second); utf8.RuneCountInString(got) != 64 {
		t.Fatalf("len %d", len(got))
	}
}

func TestMergeDedup(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.0/24")
	ip := netip.MustParseAddr("192.168.1.20")
	replies := []Host{
		{IP: ip, MAC: "AA:00:00:00:00:01"},
		{IP: ip, MAC: "AA:00:00:00:00:01"},
		{IP: ip, MAC: "AA:00:00:00:00:02"},
	}
	table := []netutil.ARPEntry{
		{IP: ip, MAC: "AA:00:00:00:00:01", Iface: "wlan0"},
		{IP: netip.MustParseAddr("192.168.1.30"), MAC: "AA:00:00:00:00:03", Iface: "wlan0"},
		{IP: netip.MustParseAddr("10.0.0.5"), MAC: "AA:00:00:00:00:04", Iface: "wlan0"},
		{IP: netip.MustParseAddr("192.168.1.40"), MAC: "AA:00:00:00:00:05", Iface: "eth0"},
	}
	self := Host{IP: netip.MustParseAddr("192.168.1.10"), MAC: "B8:27:EB:00:00:01", Self: true}
	got := merge(replies, table, "wlan0", p, &self)
	if len(got) != 4 {
		t.Fatalf("got %d hosts: %+v", len(got), got)
	}
	if !got[0].Self || got[0].IP != self.IP {
		t.Fatalf("self should sort first by IP: %+v", got)
	}
}

func TestEnrich(t *testing.T) {
	hosts := []Host{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "DA:A1:19:00:00:01"},
		{IP: netip.MustParseAddr("192.168.1.3"), MAC: "B8:27:EB:00:00:01"},
	}
	Enrich(hosts, func(mac string) string {
		if strings.HasPrefix(mac, "B8:27:EB") {
			return "Raspberry Pi"
		}
		return ""
	}, func(ip netip.Addr) string { return "h-" + ip.String() })
	if !hosts[0].Randomized || hosts[1].Randomized {
		t.Fatal("randomized flag")
	}
	if hosts[1].Vendor != "Raspberry Pi" || hosts[0].Hostname != "h-192.168.1.2" {
		t.Fatalf("%+v", hosts)
	}
}
