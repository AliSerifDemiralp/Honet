// Package health reads Raspberry Pi health figures from /sys and /proc.
// Missing files are skipped silently so it also works on other machines.
package health

import (
	"bufio"
	"bytes"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

// Health is a point-in-time reading.
type Health struct {
	TempC        *float64
	MemTotal     uint64 // bytes
	MemAvailable uint64
	DiskTotal    uint64 // filesystem holding the data directory
	DiskFree     uint64
	Uptime       time.Duration
	ProcessRSS   uint64
	Throttled    *uint32
}

// UnderVoltageNow reports firmware throttled bit 0.
func (h Health) UnderVoltageNow() bool { return h.Throttled != nil && *h.Throttled&1 != 0 }

// UnderVoltageEver reports firmware throttled bit 16 (since boot).
func (h Health) UnderVoltageEver() bool { return h.Throttled != nil && *h.Throttled&(1<<16) != 0 }

// Read collects readings from root (normally os.DirFS("/")).
func Read(root fs.FS, dataDir string) Health {
	var h Health
	if b, err := fs.ReadFile(root, "sys/class/thermal/thermal_zone0/temp"); err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
			c := v / 1000
			h.TempC = &c
		}
	}
	mem := kvKB(root, "proc/meminfo")
	h.MemTotal, h.MemAvailable = mem["MemTotal"], mem["MemAvailable"]
	h.ProcessRSS = kvKB(root, "proc/self/status")["VmRSS"]
	if b, err := fs.ReadFile(root, "proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				h.Uptime = time.Duration(v) * time.Second
			}
		}
	}
	if b, err := fs.ReadFile(root, "sys/devices/platform/soc/soc:firmware/get_throttled"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 32); err == nil {
			t := uint32(v)
			h.Throttled = &t
		}
	}
	if dataDir != "" {
		h.DiskTotal, h.DiskFree = diskUsage(dataDir)
	}
	return h
}

// kvKB parses "Key:   123 kB" lines into bytes.
func kvKB(root fs.FS, name string) map[string]uint64 {
	out := map[string]uint64{}
	b, err := fs.ReadFile(root, name)
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 2 && f[1] == "kB" {
			if n, err := strconv.ParseUint(f[0], 10, 64); err == nil {
				out[k] = n * 1024
			}
		}
	}
	return out
}
