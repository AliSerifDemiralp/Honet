package oui

import (
	"bytes"
	"testing"
)

func TestLoadSmallTable(t *testing.T) {
	var buf bytes.Buffer
	err := Encode(&buf, map[[3]byte]string{
		{0xB8, 0x27, 0xEB}: "Raspberry Pi Foundation",
		{0x00, 0x00, 0x01}: "Xerox",
		{0xFC, 0xFF, 0xFF}: "Zed",
	})
	if err != nil {
		t.Fatal(err)
	}
	tb, err := load(&buf)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"B8:27:EB:12:34:56": "Raspberry Pi Foundation",
		"b8-27-eb-12-34-56": "Raspberry Pi Foundation",
		"00:00:01:00:00:00": "Xerox",
		"FC:FF:FF:00:00:00": "Zed",
		"12:34:56:00:00:00": "",
		"B8:27":             "",
		"zz:zz:zz:00:00:00": "",
		"":                  "",
	}
	for mac, want := range cases {
		if got := tb.lookup(mac); got != want {
			t.Errorf("%q: got %q want %q", mac, got, want)
		}
	}
}

func TestEmbeddedTable(t *testing.T) {
	if got := Lookup("B8:27:EB:00:00:00"); got == "" {
		t.Fatal("Raspberry Pi prefix missing from embedded table")
	}
	if got := Lookup("FF:FF:FF:00:00:00"); got != "" {
		t.Fatalf("unexpected vendor %q", got)
	}
}
