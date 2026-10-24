package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseStunXor(t *testing.T) {
	var tx [12]byte
	for i := range tx {
		tx[i] = byte(i)
	}
	want := netip.MustParseAddrPort("203.0.113.5:40000")
	a := want.Addr().As4()
	v := make([]byte, 8)
	v[1] = 1
	binary.BigEndian.PutUint16(v[2:], want.Port()^uint16(stunMagic>>16))
	var k [4]byte
	binary.BigEndian.PutUint32(k[:], stunMagic)
	for i := 0; i < 4; i++ {
		v[4+i] = a[i] ^ k[i]
	}
	msg := make([]byte, 20, 32)
	msg[0], msg[1] = 1, 1
	binary.BigEndian.PutUint16(msg[2:], 12)
	binary.BigEndian.PutUint32(msg[4:], stunMagic)
	copy(msg[8:], tx[:])
	msg = append(msg, 0, 0x20, 0, 8)
	msg = append(msg, v...)
	got, ok := parseStun(msg, tx)
	if !ok || got != want {
		t.Fatal(got, ok)
	}
}
