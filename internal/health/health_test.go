package health

import (
	"testing"
	"testing/fstest"
	"time"
)

func TestReadPi(t *testing.T) {
	fs := fstest.MapFS{
		"sys/class/thermal/thermal_zone0/temp": {Data: []byte("48312\n")},
		"proc/meminfo":                         {Data: []byte("MemTotal:         443000 kB\nMemFree:  1000 kB\nMemAvailable:     200000 kB\n")},
		"proc/uptime":                          {Data: []byte("12345.67 11000.00\n")},
		"proc/self/status":                     {Data: []byte("Name:\thonet\nVmRSS:\t   18000 kB\n")},
		"sys/devices/platform/soc/soc:firmware/get_throttled": {Data: []byte("0x50005\n")},
	}
	h := Read(fs, "/var/lib/honet")
	if h.TempC == nil || *h.TempC < 48.3 || *h.TempC > 48.32 {
		t.Fatalf("temp %v", h.TempC)
	}
	if h.MemTotal != 443000*1024 || h.MemAvailable != 200000*1024 || h.ProcessRSS != 18000*1024 {
		t.Fatalf("mem %+v", h)
	}
	if h.Uptime != 12345*time.Second {
		t.Fatalf("uptime %v", h.Uptime)
	}
	if !h.UnderVoltageNow() || !h.UnderVoltageEver() {
		t.Fatal("throttled bits")
	}
}

func TestReadEmpty(t *testing.T) {
	h := Read(fstest.MapFS{}, "")
	if h.TempC != nil || h.Throttled != nil || h.UnderVoltageNow() || h.MemTotal != 0 {
		t.Fatalf("%+v", h)
	}
}

func TestThrottledClear(t *testing.T) {
	h := Read(fstest.MapFS{"sys/devices/platform/soc/soc:firmware/get_throttled": {Data: []byte("0x0")}}, "")
	if h.Throttled == nil || h.UnderVoltageNow() || h.UnderVoltageEver() {
		t.Fatalf("%+v", h)
	}
}
