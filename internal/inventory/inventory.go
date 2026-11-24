// Package inventory records discovered devices, their ports and the events
// derived from changes between scans.
package inventory

import (
	"errors"
	"github.com/AliSerifDemiralp/honet/internal/classify"
	"net/netip"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/risk"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

// Event kinds.
const (
	EvNewDevice         = "new_device"
	EvIPChanged         = "ip_changed"
	EvIPConflict        = "ip_conflict"
	EvGatewayMACChanged = "gateway_mac_changed"
	EvPortOpened        = "port_opened"
	EvPortClosed        = "port_closed"
	EvDeviceOffline     = "device_offline"
	EvDeviceOnline      = "device_online"
)

var (
	// ErrEmptyDiscovery means a scan found nothing besides this machine,
	// which almost always means the network is down rather than empty.
	ErrEmptyDiscovery = errors.New("discovery found no devices; is the network up?")
	// ErrBadType is returned for a manual type that classify does not know.
	ErrBadType = errors.New("unknown device type")
	// ErrNotFound is returned for an unknown device id.
	ErrNotFound = errors.New("device not found")
)

// Port is one probed TCP port of a device.
type Port struct {
	Port      int
	Open      bool
	Acked     bool
	Risk      *risk.Risk
	FirstSeen time.Time
	LastSeen  time.Time
}

// Device is one LAN device.
type Device struct {
	ID         int64
	MAC        string
	Name       string
	Notes      string
	Vendor     string
	Hostname   string
	HTTPInfo   string // web page title or Server header
	Gateway    bool   // the default gateway at the last discovery
	Probed     bool   // its ports have been scanned at least once
	AutoType   string
	ManualType string
	Known      bool
	Randomized bool
	Self       bool
	Watched    bool
	Online     bool
	WatchAfter time.Duration
	LastIP     netip.Addr
	FirstSeen  time.Time
	LastSeen   time.Time
	Ports      []Port
}

// Type is the manual type if set, otherwise the automatic guess.
func (d Device) Type() string {
	if d.ManualType != "" {
		return d.ManualType
	}
	return d.AutoType
}

// Unknown reports whether the user has not recognised this device.
func (d Device) Unknown() bool { return !d.Known && !d.Self }

// OpenPorts lists the open port numbers in ascending order.
func (d Device) OpenPorts() []int {
	var out []int
	for _, p := range d.Ports {
		if p.Open {
			out = append(out, p.Port)
		}
	}
	return out
}

// RiskyOpen lists open risky ports the user has not marked as intentional.
func (d Device) RiskyOpen() []Port {
	var out []Port
	for _, p := range d.Ports {
		if p.Open && p.Risk != nil && !p.Acked {
			out = append(out, p)
		}
	}
	return out
}

// TypeLabel is the readable name of Type.
func (d Device) TypeLabel() string { return classify.Label(d.Type()) }

// DisplayName is the user's name, else the best guess: hostname, web page
// title, type and vendor, or type and address.
func (d Device) DisplayName() string {
	switch {
	case d.Name != "":
		return d.Name
	case d.Self:
		return "Honet (this device)"
	case d.Hostname != "":
		return d.Hostname
	case d.HTTPInfo != "":
		return d.HTTPInfo
	case d.Vendor != "":
		return d.TypeLabel() + " · " + d.Vendor
	}
	return d.TypeLabel() + " at " + d.LastIP.String()
}

// Event is one recorded change.
type Event struct {
	ID         int64
	At         time.Time
	Kind       string
	DeviceID   int64
	DeviceName string
	Detail     string
	Read       bool
}

// IPRecord is one address a device has used.
type IPRecord struct {
	IP        netip.Addr
	FirstSeen time.Time
	LastSeen  time.Time
}

// GatewayAlert describes an unconfirmed change of the gateway's MAC.
type GatewayAlert struct {
	IP     netip.Addr
	OldMAC string
	NewMAC string
}

// Inventory is the device store.
type Inventory struct {
	st  *store.Store
	now func() time.Time
}

// New returns an Inventory over st using now as its clock.
func New(st *store.Store, now func() time.Time) *Inventory {
	return &Inventory{st: st, now: now}
}
