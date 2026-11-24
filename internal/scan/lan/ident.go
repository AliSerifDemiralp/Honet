package lan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AliSerifDemiralp/honet/internal/netutil"
)

// nbstatQuery is a NetBIOS node status request for the wildcard name "*".
func nbstatQuery(id uint16) []byte {
	b := make([]byte, 0, 50)
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) // flags, 1 question
	b = append(b, 0x20, 'C', 'K')               // "*" encoded: 0x2A -> 'C','K'
	for i := 0; i < 15; i++ {
		b = append(b, 'A', 'A') // padding nulls
	}
	b = append(b, 0)
	b = append(b, 0, 0x21, 0, 1) // NBSTAT, IN
	return b
}

// parseNBStat returns the workstation name (unique, suffix 0x00) from a
// node status reply.
func parseNBStat(id uint16, b []byte) (string, error) {
	if len(b) < 25 || binary.BigEndian.Uint16(b) != id || b[2]&0x80 == 0 {
		return "", errors.New("netbios: bad reply")
	}
	// Header (12), the answer name (34 bytes, or a 2-byte pointer when
	// compressed), then type, class, ttl and rdlength (10).
	nameLen := 34
	if b[12]&0xC0 == 0xC0 {
		nameLen = 2
	}
	off := 12 + nameLen + 10
	if len(b) <= off {
		return "", errors.New("netbios: truncated reply")
	}
	n := int(b[off])
	off++
	if len(b) < off+18*n {
		return "", errors.New("netbios: truncated reply")
	}
	for i := 0; i < n; i++ {
		e := b[off+18*i : off+18*(i+1)]
		group := binary.BigEndian.Uint16(e[16:])&0x8000 != 0
		if e[15] == 0 && !group {
			return netutil.CleanText(string(bytes.TrimRight(e[:15], " \x00")), 15), nil
		}
	}
	return "", errors.New("netbios: no workstation name")
}

// NetBIOSName asks ip for its NetBIOS name (Windows PCs, Samba, many NAS).
// It returns "" when the host does not answer within timeout.
func NetBIOSName(ctx context.Context, ip netip.Addr, timeout time.Duration) string {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := d.DialContext(ctx, "udp", netip.AddrPortFrom(ip, 137).String())
	if err != nil {
		return ""
	}
	defer c.Close()
	dl, _ := ctx.Deadline()
	c.SetDeadline(dl)
	var r [2]byte
	rand.Read(r[:])
	id := binary.BigEndian.Uint16(r[:])
	if _, err := c.Write(nbstatQuery(id)); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return ""
	}
	name, _ := parseNBStat(id, buf[:n])
	return name
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// httpInfoMax is how much of a page HTTPInfo reads.
const httpInfoMax = 64 << 10

// HTTPInfo fetches the web page on ip:port and returns its title, or the
// Server header if there is no title. Certificates are not verified: the
// result is only a hint, and nothing is sent but a plain GET.
func HTTPInfo(ctx context.Context, ip netip.Addr, port int, timeout time.Duration) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // read-only identification hint
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(ip.String(), strconv.Itoa(port))+"/", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "honet")
	resp, err := cl.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, httpInfoMax))
	if m := titleRE.FindSubmatch(body); m != nil {
		if t := cleanTitle(decodeText(m[1], pageCharset(resp.Header.Get("Content-Type"), body))); t != "" {
			return t
		}
	}
	return cleanTitle(resp.Header.Get("Server"))
}

var metaCharsetRE = regexp.MustCompile(`(?i)<meta[^>]+charset=["']?([a-z0-9_-]+)`)

// pageCharset finds the declared charset in the Content-Type header or a
// <meta> tag, lower-cased; "" if none.
func pageCharset(contentType string, body []byte) string {
	if _, cs, ok := strings.Cut(strings.ToLower(contentType), "charset="); ok {
		return strings.Trim(strings.TrimSpace(cs), `"'`)
	}
	if m := metaCharsetRE.FindSubmatch(body); m != nil {
		return strings.ToLower(string(m[1]))
	}
	return ""
}

// Turkish letters where ISO-8859-9 / Windows-1254 differ from Latin-1.
var latin5 = map[byte]rune{0xD0: 'Ğ', 0xDD: 'İ', 0xDE: 'Ş', 0xF0: 'ğ', 0xFD: 'ı', 0xFE: 'ş'}

// decodeText turns b into UTF-8. Routers often send Latin-1 or Turkish
// (Latin-5) pages; text that is not valid UTF-8 and names no charset is
// read as Latin-1, which keeps most Western letters.
func decodeText(b []byte, charset string) string {
	turkish := false
	switch charset {
	case "iso-8859-9", "windows-1254", "latin5", "cp1254":
		turkish = true
	case "iso-8859-1", "latin1", "windows-1252", "cp1252", "us-ascii":
	default:
		if utf8.Valid(b) {
			return string(b)
		}
	}
	var sb strings.Builder
	for _, c := range b {
		if r, ok := latin5[c]; turkish && ok {
			sb.WriteRune(r)
			continue
		}
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

func cleanTitle(s string) string {
	s = html.UnescapeString(s)
	return netutil.CleanText(strings.Join(strings.Fields(s), " "), 64)
}
