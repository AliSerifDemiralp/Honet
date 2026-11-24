package lan

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNetBIOSQueryEncoding(t *testing.T) {
	q := nbstatQuery(0x1234)
	if len(q) != 50 || q[0] != 0x12 || q[1] != 0x34 || q[12] != 0x20 || q[13] != 'C' || q[14] != 'K' || q[15] != 'A' {
		t.Fatalf("% x", q)
	}
	if q[46] != 0 || q[47] != 0x21 || q[49] != 1 {
		t.Fatalf("type/class % x", q[45:])
	}
}

// nbstatReply builds a node status response with the given 15-char names.
func nbstatReply(id uint16, names []string, groups []bool, suffix []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, []uint16{id, 0x8400, 0, 1, 0, 0})
	b.Write(nbstatQuery(id)[12:46]) // name
	binary.Write(&b, binary.BigEndian, []uint16{0x21, 1})
	binary.Write(&b, binary.BigEndian, uint32(0))
	binary.Write(&b, binary.BigEndian, uint16(1+18*len(names)+46))
	b.WriteByte(byte(len(names)))
	for i, n := range names {
		b.WriteString((n + strings.Repeat(" ", 15))[:15])
		b.WriteByte(suffix[i])
		var fl uint16
		if groups[i] {
			fl = 0x8000
		}
		binary.Write(&b, binary.BigEndian, fl)
	}
	b.Write(make([]byte, 46))
	return b.Bytes()
}

func TestNetBIOSParse(t *testing.T) {
	r := nbstatReply(7, []string{"WORKGROUP", "DESKTOP-AB12", "DESKTOP-AB12"}, []bool{true, false, false}, []byte{0, 0x20, 0})
	name, err := parseNBStat(7, r)
	if err != nil || name != "DESKTOP-AB12" {
		t.Fatalf("%q %v", name, err)
	}
	if _, err := parseNBStat(8, r); err == nil {
		t.Fatal("wrong transaction id accepted")
	}
	if _, err := parseNBStat(7, r[:40]); err == nil {
		t.Fatal("truncated reply accepted")
	}
	evil := nbstatReply(7, []string{"<b>\x07x"}, []bool{false}, []byte{0})
	if name, _ := parseNBStat(7, evil); strings.ContainsAny(name, "\x07") {
		t.Fatalf("%q", name)
	}
}

func hostPort(t *testing.T, srv *httptest.Server) (netip.Addr, int) {
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return netip.MustParseAddr(u.Hostname()), p
}

func TestHTTPInfoTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "lighttpd")
		w.Write([]byte("<html><head><TITLE>\n Archer C6 &amp; Co </TITLE></head></html>"))
	}))
	defer srv.Close()
	ip, port := hostPort(t, srv)
	if got := HTTPInfo(context.Background(), ip, port, time.Second); got != "Archer C6 & Co" {
		t.Fatalf("%q", got)
	}
}

func TestHTTPInfoServerFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Synology/DSM")
		w.Write(bytes.Repeat([]byte("x"), 200<<10)) // no title within the read limit
	}))
	defer srv.Close()
	ip, port := hostPort(t, srv)
	if got := HTTPInfo(context.Background(), ip, port, time.Second); got != "Synology/DSM" {
		t.Fatalf("%q", got)
	}
}

func TestHTTPInfoSlowServer(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	ip, port := hostPort(t, srv)
	start := time.Now()
	if got := HTTPInfo(context.Background(), ip, port, 200*time.Millisecond); got != "" || time.Since(start) > time.Second {
		t.Fatalf("%q after %v", got, time.Since(start))
	}
}

func TestNetBIOSParseCompressedName(t *testing.T) {
	full := nbstatReply(9, []string{"NAS-BOX"}, []bool{false}, []byte{0})
	// Same reply with the answer name as a 2-byte pointer to offset 12.
	short := append(append(append([]byte{}, full[:12]...), 0xC0, 0x0C), full[46:]...)
	if name, err := parseNBStat(9, short); err != nil || name != "NAS-BOX" {
		t.Fatalf("%q %v", name, err)
	}
}

func TestHTTPInfoLegacyCharset(t *testing.T) {
	cases := []struct{ ctype, body, want string }{
		{"text/html; charset=iso-8859-9", "<title>Modem Ayarlar\xfd \xde\xf0</title>", "Modem Ayarları Şğ"},
		{"text/html", "<meta charset=\"windows-1254\"><title>G\xfcvenlik \xdd</title>", "Güvenlik İ"},
		{"text/html", "<title>Caf\xe9</title>", "Café"},
		{"text/html; charset=utf-8", "<title>Çalışıyor</title>", "Çalışıyor"},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", c.ctype)
			w.Write([]byte(c.body))
		}))
		ip, port := hostPort(t, srv)
		if got := HTTPInfo(context.Background(), ip, port, time.Second); got != c.want {
			t.Errorf("%s: %q, want %q", c.ctype, got, c.want)
		}
		srv.Close()
	}
}
