// Package classify guesses a device type from vendor, open ports, hostname
// and the device's web page title. The core rules and their order come from
// the original Python scanner (net_scan.py classify_device); the printer,
// camera, NAS, media player, gateway and page title rules were added on top.
package classify

import (
	"slices"
	"strings"
)

// Types lists every type Classify can return, in display order.
var Types = []string{"router", "pc", "pc_or_laptop", "windows_pc", "server", "nas", "vm", "phone_or_tablet",
	"apple_device", "smart_tv", "media_player", "printer", "camera", "iot_or_embedded", "unknown_passive_device", "unknown"}

var labels = map[string]string{
	"router": "Router", "pc": "PC", "pc_or_laptop": "PC or laptop", "windows_pc": "Windows PC", "server": "Server",
	"nas": "NAS", "vm": "Virtual machine", "phone_or_tablet": "Phone or tablet", "apple_device": "Apple device",
	"smart_tv": "Smart TV", "media_player": "Media player", "printer": "Printer", "camera": "Camera",
	"iot_or_embedded": "Smart device", "unknown_passive_device": "Quiet device", "unknown": "Device",
}

// Label is the human-readable name of a type.
func Label(t string) string {
	if l, ok := labels[t]; ok {
		return l
	}
	return "Device"
}

// Input is what is known about a device.
type Input struct {
	Vendor     string
	Ports      []int // open TCP ports
	Hostname   string
	HTTP       string // web page title or Server header
	Randomized bool   // locally administered (private) MAC
	Gateway    bool   // the network's default gateway
}

// IsType reports whether s is one of Types.
func IsType(s string) bool { return slices.Contains(Types, s) }

var (
	phoneVendors  = []string{"apple", "samsung", "xiaomi", "huawei", "honor", "oppo", "oneplus", "google", "motorola", "realme", "vivo"}
	tvVendors     = []string{"lg", "sony", "philips", "tcl", "hisense", "vestel", "arcelik", "beko", "samsung", "panasonic"}
	routerVendors = []string{"zte", "tp-link", "tplink", "ubiquiti", "mikrotik", "keenetic", "asus", "huawei", "netgear", "cisco", "zyxel"}
	vmVendors     = []string{"vmware", "virtualbox", "oracle", "qemu", "xen"}
	pcVendors     = []string{"intel", "realtek", "dell", "hp", "lenovo", "asus", "acer", "msi"}
)

// Page title keywords, checked in this order.
var titleRules = []struct {
	words []string
	typ   string
}{
	{[]string{"printer", "laserjet", "officejet", "deskjet", "pixma", "epson", "brother", "kyocera"}, "printer"},
	{[]string{"camera", "ipcam", "nvr", "dvr", "hikvision", "dahua", "reolink"}, "camera"},
	{[]string{"diskstation", "synology", "qnap", "truenas", "openmediavault", "nas"}, "nas"},
	{[]string{"router", "modem", "gateway", "archer", "fritz!box", "airties", "zyxel", "mikrotik", "openwrt", "huawei hg", "keenetic", "zxhn", "zte", "tp-link", "netgear", "linksys", "asus router"}, "router"},
}

// hasWord reports whether s contains w as a whole word.
func hasWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		a, b := i+j, i+j+len(w)
		if (a == 0 || !isAlnum(s[a-1])) && (b == len(s) || !isAlnum(s[b])) {
			return true
		}
		i = a + 1
	}
}

func isAlnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func hasAny(ports []int, want ...int) bool {
	for _, w := range want {
		if slices.Contains(ports, w) {
			return true
		}
	}
	return false
}

// Classify returns the guessed device type.
func Classify(in Input) string {
	v := strings.ToLower(in.Vendor)
	h := strings.ToLower(in.Hostname)
	title := strings.ToLower(in.HTTP)
	ports, randomized := in.Ports, in.Randomized
	none := len(ports) == 0

	switch {
	case containsAny(v, vmVendors):
		return "vm"
	case in.Gateway:
		return "router"
	case hasAny(ports, 53) && hasAny(ports, 67, 68, 80, 443):
		return "router"
	case containsAny(v, routerVendors) && hasAny(ports, 53):
		return "router"
	}
	switch {
	case hasAny(ports, 9100, 631, 515):
		return "printer"
	case hasAny(ports, 554, 8554):
		return "camera"
	case hasAny(ports, 5000) && hasAny(ports, 5001), hasAny(ports, 548, 2049):
		return "nas"
	case hasAny(ports, 62078):
		// iOS devices listen on 62078 (lockdown) even with a private MAC.
		return "phone_or_tablet"
	}
	for _, r := range titleRules {
		for _, w := range r.words {
			if hasWord(title, w) {
				return r.typ
			}
		}
	}
	if containsAny(v, tvVendors) && (none || hasAny(ports, 8008, 8080, 8443, 80, 443)) {
		return "smart_tv"
	}
	if hasAny(ports, 8008, 8009) {
		return "media_player"
	}
	if strings.Contains(v, "apple") {
		if !none && hasAny(ports, 80, 443, 7000, 7100) {
			return "apple_device"
		}
		return "phone_or_tablet"
	}
	switch {
	case hasAny(ports, 7000) && !hasAny(ports, 22, 445, 3389):
		return "media_player" // AirPlay receiver
	case containsAny(v, phoneVendors):
		return "phone_or_tablet"
	case randomized && none:
		return "phone_or_tablet"
	case hasAny(ports, 3389, 445, 5985, 5986):
		return "windows_pc"
	case hasAny(ports, 22) && hasAny(ports, 5432, 3306, 6443, 9200, 9090, 5601, 27017, 6379):
		return "server"
	case hasAny(ports, 22) && hasAny(ports, 80, 443, 8000, 8080, 8443, 5000, 3000):
		return "server"
	case hasAny(ports, 5432, 3306, 1433, 1521, 27017, 6379, 9042, 9200, 11211):
		return "server"
	case hasAny(ports, 6443, 10250, 9092, 2181, 9090, 5601):
		return "server"
	}
	if containsAny(v, pcVendors) {
		if hasAny(ports, 22, 80) {
			return "pc"
		}
		if none {
			return "pc_or_laptop"
		}
	}
	switch {
	case strings.Contains(h, "android") || strings.Contains(h, "iphone") || strings.Contains(h, "ipad"):
		return "phone_or_tablet"
	case strings.Contains(h, "tv") || strings.Contains(h, "bravia"):
		return "smart_tv"
	case none:
		return "unknown_passive_device"
	case hasAny(ports, 80, 443, 8000, 8080, 8443) && len(ports) <= 3:
		return "iot_or_embedded"
	}
	return "unknown"
}
