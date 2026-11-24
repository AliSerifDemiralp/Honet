package netmon

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type icmpPinger struct{}

// NewICMP returns a pinger using raw ICMP sockets (CAP_NET_RAW), or
// unprivileged datagram ICMP sockets where the kernel allows them.
func NewICMP() Pinger { return icmpPinger{} }

func (icmpPinger) Ping(ctx context.Context, ip netip.Addr, n int, timeout time.Duration) ([]time.Duration, error) {
	raw, dgram, any, proto := "ip4:icmp", "udp4", "0.0.0.0", 1
	var reqType icmp.Type = ipv4.ICMPTypeEcho
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	if ip.Is6() && !ip.Is4In6() {
		raw, dgram, any, proto = "ip6:ipv6-icmp", "udp6", "::", 58
		reqType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	ip = ip.Unmap()
	privileged := true
	c, err := icmp.ListenPacket(raw, any)
	if err != nil {
		privileged = false
		if c, err = icmp.ListenPacket(dgram, any); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	defer c.Close()

	var dst net.Addr = &net.IPAddr{IP: ip.AsSlice()}
	if !privileged {
		dst = &net.UDPAddr{IP: ip.AsSlice()}
	}
	id := os.Getpid() & 0xffff
	seq0 := rand.IntN(0x8000)
	out := make([]time.Duration, n)
	buf := make([]byte, 1500)
	for i := range out {
		out[i] = -1
		if ctx.Err() != nil {
			continue
		}
		seq := (seq0 + i) & 0xffff
		msg := icmp.Message{Type: reqType, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("honet-ping")}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return nil, err
		}
		sent := time.Now()
		if _, err := c.WriteTo(b, dst); err != nil {
			continue // e.g. network unreachable: counts as lost
		}
		deadline := sent.Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		c.SetReadDeadline(deadline)
		for {
			k, peer, err := c.ReadFrom(buf)
			if err != nil {
				break // timeout
			}
			if !samePeer(peer, ip) {
				continue
			}
			rm, err := icmp.ParseMessage(proto, buf[:k])
			if err != nil || rm.Type != replyType {
				continue
			}
			echo, ok := rm.Body.(*icmp.Echo)
			// Unprivileged sockets get a kernel-chosen ID, so only the
			// sequence number can be checked there.
			if !ok || echo.Seq != seq || (privileged && echo.ID != id) {
				continue
			}
			out[i] = time.Since(sent)
			break
		}
	}
	return out, nil
}

func samePeer(a net.Addr, ip netip.Addr) bool {
	var b net.IP
	switch v := a.(type) {
	case *net.IPAddr:
		b = v.IP
	case *net.UDPAddr:
		b = v.IP
	default:
		return false
	}
	p, ok := netip.AddrFromSlice(b)
	return ok && p.Unmap() == ip
}
