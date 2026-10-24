package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNS(t *testing.T) {
	m := &Mesh{roster: &Roster{Domain: "mesh", Members: []Member{{Name: "box", IP: "10.77.0.9"}}}}
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	go (&dns.Server{PacketConn: l, Handler: dns.HandlerFunc(m.dnsHandler)}).ActivateAndServe()
	c := &dns.Client{Timeout: 2 * time.Second}
	ask := func(n string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(n, dns.TypeA)
		r, _, err := c.Exchange(q, l.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := ask("box.mesh."); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "10.77.0.9" {
		t.Fatal(r)
	}
	if r := ask("nope.mesh."); r.Rcode != dns.RcodeNameError {
		t.Fatal(r.Rcode)
	}
	if r := ask("example.com."); r.Rcode != dns.RcodeRefused {
		t.Fatal(r.Rcode)
	}
}
