// Command gen converts the IEEE MA-L list (https://standards-oui.ieee.org/oui/oui.csv)
// into honet's embedded vendor table.
package main

import (
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/AliSerifDemiralp/honet/internal/netutil"
	"github.com/AliSerifDemiralp/honet/internal/oui"
)

func main() {
	in := flag.String("in", "oui.csv", "IEEE oui.csv")
	out := flag.String("out", "oui.bin.gz", "output table")
	flag.Parse()

	f, err := os.Open(*in)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	entries := map[[3]byte]string{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if len(rec) < 3 || rec[0] != "MA-L" || len(rec[1]) != 6 {
			continue
		}
		b, err := hex.DecodeString(rec[1])
		if err != nil {
			continue
		}
		name := netutil.CleanText(rec[2], 48)
		if name == "" {
			continue
		}
		entries[[3]byte{b[0], b[1], b[2]}] = name
	}
	o, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	if err := oui.Encode(o, entries); err != nil {
		log.Fatal(err)
	}
	if err := o.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d prefixes written to %s\n", len(entries), *out)
}
