package lan

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ParsePortSpec parses a list such as "22,80,8000-8100" into sorted,
// unique ports between 1 and 65535.
func ParsePortSpec(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("no ports given")
	}
	seen := make([]bool, 65536)
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = parsePort(hi); err != nil {
				return nil, err
			}
			if b < a {
				return nil, fmt.Errorf("port range %q is backwards", part)
			}
		}
		for p := a; p <= b; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q is not a port number (1-65535)", s)
	}
	return n, nil
}

// PortSpec writes sorted ports back as a compact list with ranges.
func PortSpec(ports []int) string {
	var b strings.Builder
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(ports[i]))
		if j > i {
			b.WriteString("-" + strconv.Itoa(ports[j]))
		}
		i = j + 1
	}
	return b.String()
}

// Profiles lists the port scan choices offered in the UI.
var Profiles = []struct{ ID, Label string }{
	{"common", "Common (" + strconv.Itoa(len(CommonPorts)) + " ports)"},
	{"well-known", "Well-known (1-1024)"},
	{"extended", "Extended (1-10000)"},
	{"all", "All (1-65535, slow)"},
	{"custom", "Custom"},
}

// ProfilePorts returns the ports of a profile and the spec a job stores
// for them ("" for the common list).
func ProfilePorts(profile, custom string) ([]int, string, error) {
	var spec string
	switch profile {
	case "", "common":
		return CommonPorts, "", nil
	case "well-known":
		spec = "1-1024"
	case "extended":
		spec = "1-10000"
	case "all":
		spec = "1-65535"
	case "custom":
		ports, err := ParsePortSpec(custom)
		if err != nil {
			return nil, "", err
		}
		return ports, PortSpec(ports), nil
	default:
		return nil, "", fmt.Errorf("unknown port profile %q", profile)
	}
	ports, err := ParsePortSpec(spec)
	return ports, spec, err
}

// JobPorts returns the ports a stored job spec stands for.
func JobPorts(spec string) ([]int, error) {
	if spec == "" {
		return CommonPorts, nil
	}
	return ParsePortSpec(spec)
}

var services = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
	80: "http", 110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 162: "snmp-trap",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 515: "printer", 548: "afp", 554: "rtsp", 587: "submission",
	631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1883: "mqtt", 1900: "upnp", 2049: "nfs",
	2181: "zookeeper", 3000: "http-alt", 3306: "mysql", 3389: "rdp", 5000: "upnp/http", 5001: "https-alt",
	5353: "mdns", 5357: "wsd", 5432: "postgres", 5601: "kibana", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
	6379: "redis", 6443: "kubernetes", 7000: "airplay", 8000: "http-alt", 8008: "chromecast", 8009: "chromecast",
	8080: "http-proxy", 8443: "https-alt", 8554: "rtsp-alt", 8883: "mqtt-tls", 9042: "cassandra", 9090: "prometheus",
	9092: "kafka", 9100: "printer", 9200: "elasticsearch", 10250: "kubelet", 11211: "memcached", 27017: "mongodb",
	32400: "plex", 49152: "upnp", 62078: "iphone-sync",
}

// ServiceName is the usual service on a port, or "".
func ServiceName(port int) string { return services[port] }
