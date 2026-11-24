package classify

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		vendor     string
		ports      []int
		hostname   string
		randomized bool
		want       string
	}{
		{"VMware, Inc.", nil, "", false, "vm"},
		{"", []int{53, 80}, "", false, "router"},
		{"TP-LINK", []int{53}, "", false, "router"},
		{"LG Electronics", []int{8008}, "", false, "smart_tv"},
		{"Apple, Inc.", nil, "", false, "phone_or_tablet"},
		{"Apple, Inc.", []int{7000}, "", false, "apple_device"},
		{"Apple, Inc.", []int{22}, "", false, "phone_or_tablet"},
		{"Xiaomi", []int{8080}, "", false, "phone_or_tablet"},
		{"", nil, "", true, "phone_or_tablet"},
		{"", []int{3389}, "", false, "windows_pc"},
		{"", []int{22, 5432}, "", false, "server"},
		{"", []int{22, 8080}, "", false, "server"},
		{"", []int{6379}, "", false, "server"},
		{"", []int{9092}, "", false, "server"},
		{"Intel Corporate", []int{22}, "", false, "pc"},
		{"Dell Inc.", nil, "", false, "pc_or_laptop"},
		{"", nil, "my-iphone", false, "phone_or_tablet"},
		{"", nil, "bravia-kd55", false, "smart_tv"},
		{"", nil, "", false, "unknown_passive_device"},
		{"", []int{80}, "", false, "iot_or_embedded"},
		{"", []int{25, 110, 143, 465}, "", false, "unknown"},
	}
	for _, c := range cases {
		if got := Classify(Input{Vendor: c.vendor, Ports: c.ports, Hostname: c.hostname, Randomized: c.randomized}); got != c.want {
			t.Errorf("Classify(%q,%v,%q,%v) = %q, want %q", c.vendor, c.ports, c.hostname, c.randomized, got, c.want)
		}
	}
}

func TestTypesListed(t *testing.T) {
	if len(Types) != 16 || !IsType("server") || IsType("toaster") {
		t.Fatalf("%v", Types)
	}
}

func TestClassifyNewTypes(t *testing.T) {
	cases := []struct {
		in   Input
		want string
	}{
		{Input{Vendor: "HP Inc.", Ports: []int{80, 443, 9100}}, "printer"},
		{Input{Ports: []int{631}}, "printer"},
		{Input{Ports: []int{80, 554}}, "camera"},
		{Input{Ports: []int{22, 80, 445, 5000, 5001}}, "nas"},
		{Input{Ports: []int{2049}}, "nas"},
		{Input{Ports: []int{8008, 8009}}, "media_player"},
		{Input{Vendor: "Sonos", Ports: []int{7000}}, "media_player"},
		{Input{Vendor: "LG Electronics", Ports: []int{8008}}, "smart_tv"},
		{Input{Randomized: true, Ports: []int{62078}}, "phone_or_tablet"},
		{Input{Vendor: "Apple, Inc.", Ports: []int{7000, 62078}}, "phone_or_tablet"},
		{Input{Ports: []int{22, 80}, HTTP: "Archer C6 Router"}, "router"},
		{Input{Ports: []int{443}, HTTP: "ZXHN H298A V1.0"}, "router"},
		{Input{Ports: []int{80}, HTTP: "HP LaserJet MFP"}, "printer"},
		{Input{Ports: []int{80}, HTTP: "DiskStation"}, "nas"},
		{Input{Ports: []int{80}, HTTP: "NVR Login"}, "camera"},
		{Input{Ports: []int{80}, HTTP: "Welcome to nginx!"}, "iot_or_embedded"},
	}
	for _, c := range cases {
		if got := Classify(c.in); got != c.want {
			t.Errorf("Classify(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGatewayIsRouter(t *testing.T) {
	for _, in := range []Input{{Gateway: true}, {Gateway: true, Vendor: "Intel Corporate", Ports: []int{22, 80}}} {
		if got := Classify(in); got != "router" {
			t.Errorf("%+v: %q", in, got)
		}
	}
}

func TestLabel(t *testing.T) {
	if Label("phone_or_tablet") != "Phone or tablet" || Label("nas") != "NAS" || Label("unknown") != "Device" {
		t.Fatal(Label("phone_or_tablet"), Label("nas"), Label("unknown"))
	}
}
