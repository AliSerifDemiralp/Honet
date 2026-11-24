package lan

import (
	"slices"
	"testing"
)

func TestParsePortSpec(t *testing.T) {
	got, err := ParsePortSpec(" 443, 22,80 ,8000-8003,22 ")
	if err != nil || !slices.Equal(got, []int{22, 80, 443, 8000, 8001, 8002, 8003}) {
		t.Fatalf("%v %v", got, err)
	}
	if all, err := ParsePortSpec("1-65535"); err != nil || len(all) != 65535 {
		t.Fatalf("%d %v", len(all), err)
	}
	for _, bad := range []string{"", "0", "65536", "80-20", "a", "1-2-3", "-5", "22,,80", "1-65535,1-70000"} {
		if _, err := ParsePortSpec(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestProfilePorts(t *testing.T) {
	cases := []struct {
		profile, custom string
		n               int
		spec            string
	}{
		{"common", "", len(CommonPorts), ""},
		{"", "", len(CommonPorts), ""},
		{"well-known", "", 1024, "1-1024"},
		{"extended", "", 10000, "1-10000"},
		{"all", "", 65535, "1-65535"},
		{"custom", "80, 8000-8001", 3, "80,8000-8001"},
	}
	for _, c := range cases {
		ports, spec, err := ProfilePorts(c.profile, c.custom)
		if err != nil || len(ports) != c.n || spec != c.spec {
			t.Errorf("%s: %d %q %v", c.profile, len(ports), spec, err)
		}
	}
	if _, _, err := ProfilePorts("custom", "99999"); err == nil {
		t.Fatal("bad custom accepted")
	}
	if _, _, err := ProfilePorts("nmap", ""); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestCommonPortsIdentifyDevices(t *testing.T) {
	for _, p := range []int{9100, 631, 554, 548, 2049, 5001, 7000, 8009, 62078} {
		if !slices.Contains(CommonPorts, p) {
			t.Errorf("common ports lack %d", p)
		}
	}
}

func TestServiceName(t *testing.T) {
	if ServiceName(22) != "ssh" || ServiceName(9100) != "printer" || ServiceName(40000) != "" {
		t.Fatal(ServiceName(22), ServiceName(9100))
	}
}

func TestProbeConcurrencyScales(t *testing.T) {
	if probeConcurrency(32, 57) != 32 || probeConcurrency(32, 1024) != 32 {
		t.Fatal("small scans keep the base")
	}
	if c := probeConcurrency(32, 65535); c < 128 || c > 256 {
		t.Fatalf("wide scan concurrency %d", c)
	}
}
