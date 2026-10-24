package main

import (
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func TestRosterAccept(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(sk)
	other := nostr.GeneratePrivateKey()
	r := &Roster{Network: "n1", CIDR: "10.77.0.0/16", Admins: []string{pub}, Version: 2,
		Members: []Member{{Pubkey: pub, Name: "a", IP: "10.77.0.1"}}}
	ev, err := r.sign(sk)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := acceptRoster(&ev, "n1", []string{pub}, nil, now); err != nil {
		t.Fatal("正しい名簿を拒否:", err)
	}
	if _, err := acceptRoster(&ev, "n2", []string{pub}, nil, now); err == nil {
		t.Fatal("別ネットワークを受理")
	}
	if _, err := acceptRoster(&ev, "n1", []string{pub}, &Roster{Version: 2}, now); err == nil {
		t.Fatal("同じ版を受理")
	}
	bad, _ := r.sign(other)
	if _, err := acceptRoster(&bad, "n1", []string{pub}, nil, now); err == nil {
		t.Fatal("管理者以外の署名を受理")
	}
	tampered := ev
	tampered.Content = `{"network":"n1","cidr":"10.77.0.0/16","version":3,"members":[]}`
	if _, err := acceptRoster(&tampered, "n1", []string{pub}, nil, now); err == nil {
		t.Fatal("改ざんを受理")
	}
	r2 := *r
	r2.Members = append(r2.Members, Member{Pubkey: pub, Name: "b", IP: "10.78.0.1"})
	if _, err := r2.sign(sk); err == nil {
		t.Fatal("範囲外 IP を署名")
	}
}

func TestNextIP(t *testing.T) {
	r := &Roster{CIDR: "10.77.0.0/16", Members: []Member{{IP: "10.77.0.1"}, {IP: "10.77.0.2"}}}
	ip, _ := r.nextIP()
	if ip.String() != "10.77.0.3" {
		t.Fatal(ip)
	}
}
