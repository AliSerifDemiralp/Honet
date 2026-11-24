package risk

import "testing"

func TestLookup(t *testing.T) {
	r, ok := Lookup(23)
	if !ok || r.Name != "Telnet" || r.Reason == "" {
		t.Fatalf("%+v %v", r, ok)
	}
	if _, ok := Lookup(443); ok {
		t.Fatal("443 should not be risky")
	}
	for _, p := range []int{21, 23, 3389, 5900, 445, 139, 1433, 3306, 5432, 27017, 6379, 9200, 11211, 161} {
		r, ok := Lookup(p)
		if !ok || r.Reason == "" || r.Port != p {
			t.Errorf("port %d: %+v %v", p, r, ok)
		}
	}
}
