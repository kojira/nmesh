package main

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func netstackPing(ctx context.Context, tnet *netstack.Net, src, dst netip.Addr) (time.Duration, error) {
	c, err := tnet.DialPingAddr(src, dst)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	req := icmp.Echo{ID: rand.Intn(1 << 16), Seq: rand.Intn(1 << 16), Data: []byte("nmesh-ping")}
	b, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &req}).Marshal(nil)
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(3 * time.Second)
	}
	c.SetReadDeadline(dl)
	t0 := time.Now()
	if _, err := c.Write(b); err != nil {
		return 0, err
	}
	rb := make([]byte, 1500)
	for {
		n, err := c.Read(rb)
		if err != nil {
			return 0, err
		}
		msg, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}
		if e, ok := msg.Body.(*icmp.Echo); ok && e.Seq == req.Seq && bytes.Equal(e.Data, req.Data) {
			return time.Since(t0), nil
		}
	}
}

var errNoPing = fmt.Errorf("この形式では使えません")
