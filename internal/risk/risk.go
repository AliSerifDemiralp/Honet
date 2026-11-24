// Package risk flags open ports that are commonly unsafe on a home network.
package risk

// Risk explains why an open port deserves attention.
type Risk struct {
	Port   int
	Name   string
	Reason string
}

var table = map[int]Risk{}

func init() {
	for _, r := range []Risk{
		{21, "FTP", "Sends passwords and files in plain text; use SFTP instead."},
		{23, "Telnet", "Sends passwords in plain text; use SSH instead."},
		{3389, "RDP", "Remote desktop is a frequent brute-force target; keep it off unless needed."},
		{5900, "VNC", "Remote screen access often has weak or no authentication."},
		{445, "SMB", "File sharing exposes files and has a long history of worms."},
		{139, "NetBIOS", "Legacy Windows file sharing that leaks device and user names."},
		{1433, "MSSQL", "A database reachable from the whole network; restrict it to the hosts that need it."},
		{3306, "MySQL", "A database reachable from the whole network; restrict it to the hosts that need it."},
		{5432, "PostgreSQL", "A database reachable from the whole network; restrict it to the hosts that need it."},
		{27017, "MongoDB", "Often runs without authentication; restrict access."},
		{6379, "Redis", "Often runs without authentication and allows code execution if exposed."},
		{9200, "Elasticsearch", "Often runs without authentication and exposes all stored data."},
		{11211, "Memcached", "Has no authentication; anyone on the network can read the cache."},
		{161, "SNMP", "Default community strings let anyone read device configuration."},
	} {
		table[r.Port] = r
	}
}

// Lookup returns the risk for port, if it is on the list.
func Lookup(port int) (Risk, bool) {
	r, ok := table[port]
	return r, ok
}
