// Package oui maps MAC address prefixes to vendor names using an embedded,
// compact IEEE MA-L table searched with binary search (no map in memory).
package oui

//go:generate go run ./gen -in oui.csv -out oui.bin.gz

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
)

//go:embed oui.bin.gz
var embedded []byte

const recSize = 3 + 4 + 2

type table struct {
	recs  []byte // n records of prefix(3) offset(4) len(2), sorted by prefix
	names []byte
}

var (
	once sync.Once
	tab  *table
)

// Lookup returns the vendor for mac, or "" if unknown.
func Lookup(mac string) string {
	once.Do(func() {
		t, err := load(bytes.NewReader(embedded))
		if err != nil {
			t = &table{}
		}
		tab = t
	})
	return tab.lookup(mac)
}

func (t *table) lookup(mac string) string {
	clean := strings.NewReplacer(":", "", "-", "").Replace(mac)
	if len(clean) < 6 {
		return ""
	}
	p, err := hex.DecodeString(clean[:6])
	if err != nil {
		return ""
	}
	n := len(t.recs) / recSize
	i := sort.Search(n, func(i int) bool { return bytes.Compare(t.recs[i*recSize:i*recSize+3], p) >= 0 })
	if i == n {
		return ""
	}
	r := t.recs[i*recSize : (i+1)*recSize]
	if !bytes.Equal(r[:3], p) {
		return ""
	}
	off := binary.BigEndian.Uint32(r[3:7])
	l := binary.BigEndian.Uint16(r[7:9])
	if int(off)+int(l) > len(t.names) {
		return ""
	}
	return string(t.names[off : off+uint32(l)])
}

func load(r io.Reader) (*table, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, errors.New("oui: short table")
	}
	n := int(binary.BigEndian.Uint32(data))
	if len(data) < 4+n*recSize {
		return nil, errors.New("oui: truncated table")
	}
	return &table{recs: data[4 : 4+n*recSize], names: data[4+n*recSize:]}, nil
}

// Encode writes entries in the gzip-compressed table format read by Lookup.
func Encode(w io.Writer, entries map[[3]byte]string) error {
	keys := make([][3]byte, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	var recs, names bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(keys)))
	recs.Write(hdr[:])
	for _, k := range keys {
		name := entries[k]
		if len(name) > 0xFFFF {
			name = name[:0xFFFF]
		}
		var rec [recSize]byte
		copy(rec[:3], k[:])
		binary.BigEndian.PutUint32(rec[3:7], uint32(names.Len()))
		binary.BigEndian.PutUint16(rec[7:9], uint16(len(name)))
		recs.Write(rec[:])
		names.WriteString(name)
	}
	zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(recs.Bytes()); err != nil {
		return err
	}
	if _, err := zw.Write(names.Bytes()); err != nil {
		return err
	}
	return zw.Close()
}
