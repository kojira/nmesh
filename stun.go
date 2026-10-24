package main

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

// 最小限の STUN（RFC 5389）Binding リクエスト。WireGuard と同じソケットから送り、
// 外から見えた自分の住所（XOR-MAPPED-ADDRESS）を得る。

const stunMagic = 0x2112A442

type stunClient struct {
	bind    *udpBind
	mu      sync.Mutex
	pending map[[12]byte]chan netip.AddrPort
}

func newStunClient(b *udpBind) *stunClient {
	return &stunClient{bind: b, pending: map[[12]byte]chan netip.AddrPort{}}
}

func isStunResponse(b []byte) bool {
	return len(b) >= 20 && b[0] == 0x01 && b[1] == 0x01 && binary.BigEndian.Uint32(b[4:8]) == stunMagic
}

// handle は bind から呼ばれる。STUN 応答なら true。
func (s *stunClient) handle(b []byte) bool {
	if !isStunResponse(b) {
		return false
	}
	var tx [12]byte
	copy(tx[:], b[8:20])
	s.mu.Lock()
	ch := s.pending[tx]
	s.mu.Unlock()
	if ch == nil {
		return true
	}
	if ap, ok := parseStun(b, tx); ok {
		select {
		case ch <- ap:
		default:
		}
	}
	return true
}

func parseStun(b []byte, tx [12]byte) (netip.AddrPort, bool) {
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if 20+l > len(b) {
		return netip.AddrPort{}, false
	}
	attrs := b[20 : 20+l]
	var mapped netip.AddrPort
	found := false
	for len(attrs) >= 4 {
		t := binary.BigEndian.Uint16(attrs[0:2])
		al := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+al > len(attrs) {
			break
		}
		v := attrs[4 : 4+al]
		switch t {
		case 0x0020: // XOR-MAPPED-ADDRESS
			if ap, ok := decodeAddr(v, true, tx); ok {
				return ap, true
			}
		case 0x0001: // MAPPED-ADDRESS
			if ap, ok := decodeAddr(v, false, tx); ok {
				mapped, found = ap, true
			}
		}
		attrs = attrs[4+((al+3)&^3):]
	}
	return mapped, found
}

func decodeAddr(v []byte, xor bool, tx [12]byte) (netip.AddrPort, bool) {
	if len(v) < 8 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], stunMagic)
	copy(key[4:], tx[:])
	if xor {
		port ^= uint16(stunMagic >> 16)
	}
	switch v[1] {
	case 0x01:
		var a [4]byte
		copy(a[:], v[4:8])
		if xor {
			for i := range a {
				a[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case 0x02:
		if len(v) < 20 {
			return netip.AddrPort{}, false
		}
		var a [16]byte
		copy(a[:], v[4:20])
		if xor {
			for i := range a {
				a[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	}
	return netip.AddrPort{}, false
}

// query は全サーバーへ問い合わせ、得られた外側の住所（重複なし）を返す。
func (s *stunClient) query(servers []string, timeout time.Duration) []netip.AddrPort {
	type req struct {
		tx [12]byte
		ch chan netip.AddrPort
	}
	var reqs []req
	for _, srv := range servers {
		host, port, err := net.SplitHostPort(srv)
		if err != nil {
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		var p uint16
		if pp, err := net.LookupPort("udp", port); err == nil {
			p = uint16(pp)
		}
		seen4, seen6 := false, false
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			a = a.Unmap()
			if a.Is4() && seen4 || a.Is6() && seen6 {
				continue
			}
			if a.Is4() {
				seen4 = true
			} else {
				seen6 = true
			}
			var r req
			rand.Read(r.tx[:])
			r.ch = make(chan netip.AddrPort, 1)
			s.mu.Lock()
			s.pending[r.tx] = r.ch
			s.mu.Unlock()
			msg := make([]byte, 20)
			binary.BigEndian.PutUint16(msg[0:2], 0x0001)
			binary.BigEndian.PutUint32(msg[4:8], stunMagic)
			copy(msg[8:], r.tx[:])
			if err := s.bind.SendRaw(msg, netip.AddrPortFrom(a, p)); err == nil {
				reqs = append(reqs, r)
			}
		}
	}
	deadline := time.Now().Add(timeout)
	seen := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	got := make([]bool, len(reqs))
	for remaining := len(reqs); remaining > 0 && time.Now().Before(deadline); {
		for i, r := range reqs {
			if got[i] {
				continue
			}
			select {
			case ap := <-r.ch:
				got[i] = true
				remaining--
				ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
				if !seen[ap] {
					seen[ap] = true
					out = append(out, ap)
				}
			default:
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.mu.Lock()
	for _, r := range reqs {
		delete(s.pending, r.tx)
	}
	s.mu.Unlock()
	return out
}
