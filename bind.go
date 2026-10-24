package main

import (
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// udpBind は WireGuard・STUN・ホールパンチで1つのUDPソケットを共有するための conn.Bind。
// WireGuard 以外のパケット（STUN応答、パンチ）は onControl に渡し、WireGuard には渡さない。
type udpBind struct {
	mu        sync.Mutex
	c         *net.UDPConn
	onControl func(b []byte, from netip.AddrPort) bool // true なら消費済み
}

type endpoint struct{ ap netip.AddrPort }

func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) DstToString() string { return e.ap.String() }
func (e endpoint) DstToBytes() []byte  { b, _ := e.ap.MarshalBinary(); return b }
func (e endpoint) DstIP() netip.Addr   { return e.ap.Addr() }
func (e endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (b *udpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.c = c
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, from, err := c.ReadFromUDPAddrPort(packets[0])
			if err != nil {
				return 0, err
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			if b.onControl != nil && b.onControl(packets[0][:n], from) {
				continue
			}
			sizes[0] = n
			eps[0] = endpoint{from}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *udpBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c == nil {
		return nil
	}
	err := b.c.Close()
	b.c = nil
	return err
}

func (b *udpBind) SetMark(uint32) error { return nil }
func (b *udpBind) BatchSize() int       { return 1 }

func (b *udpBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return endpoint{netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}

func (b *udpBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	for _, buf := range bufs {
		if err := b.SendRaw(buf, e.ap); err != nil {
			return err
		}
	}
	return nil
}

// SendRaw は制御パケット（STUN・パンチ）用。
func (b *udpBind) SendRaw(buf []byte, to netip.AddrPort) error {
	b.mu.Lock()
	c := b.c
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	_, err := c.WriteToUDPAddrPort(buf, to)
	return err
}
