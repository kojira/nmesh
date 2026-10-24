package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

type Member struct {
	Pubkey string `json:"pubkey"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
}

type Roster struct {
	Network string   `json:"network"`
	Name    string   `json:"name"`
	Version int64    `json:"version"`
	CIDR    string   `json:"cidr"`
	Domain  string   `json:"domain"`
	Admins  []string `json:"admins"`
	Members []Member `json:"members"`
}

func newNetworkID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (r *Roster) member(pub string) *Member {
	for i := range r.Members {
		if r.Members[i].Pubkey == pub {
			return &r.Members[i]
		}
	}
	return nil
}

func (r *Roster) byName(name string) *Member {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for i := range r.Members {
		n := strings.ToLower(r.Members[i].Name)
		if n == name || (r.Domain != "" && n+"."+r.Domain == name) {
			return &r.Members[i]
		}
	}
	return nil
}

// nextIP は CIDR 内で未使用の最小アドレス（.0 と .1 の網・予約を避ける）を返す。
func (r *Roster) nextIP() (netip.Addr, error) {
	p, err := netip.ParsePrefix(r.CIDR)
	if err != nil {
		return netip.Addr{}, err
	}
	used := map[netip.Addr]bool{}
	for _, m := range r.Members {
		if a, err := netip.ParseAddr(m.IP); err == nil {
			used[a] = true
		}
	}
	a := p.Masked().Addr().Next()
	for p.Contains(a) {
		b := a.As4()
		if b[3] != 0 && b[3] != 255 && !used[a] {
			return a, nil
		}
		a = a.Next()
	}
	return netip.Addr{}, fmt.Errorf("%s に空きがありません", r.CIDR)
}

func (r *Roster) validate() error {
	p, err := netip.ParsePrefix(r.CIDR)
	if err != nil || !p.Addr().Is4() {
		return fmt.Errorf("cidr が不正: %q", r.CIDR)
	}
	seenIP, seenPub, seenName := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range r.Members {
		a, err := netip.ParseAddr(m.IP)
		if err != nil || !p.Contains(a) {
			return fmt.Errorf("%s の IP %q が範囲外", m.Name, m.IP)
		}
		if len(m.Pubkey) != 64 {
			return fmt.Errorf("%s の pubkey が不正", m.Name)
		}
		if seenIP[m.IP] || seenPub[m.Pubkey] || seenName[strings.ToLower(m.Name)] {
			return fmt.Errorf("重複: %s", m.Name)
		}
		seenIP[m.IP], seenPub[m.Pubkey], seenName[strings.ToLower(m.Name)] = true, true, true
	}
	return nil
}

func (r *Roster) sign(sk string) (nostr.Event, error) {
	if err := r.validate(); err != nil {
		return nostr.Event{}, err
	}
	b, _ := json.Marshal(r)
	ev := nostr.Event{
		Kind:      KindRoster,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"d", r.Network}, {"v", fmt.Sprint(r.Version)}},
		Content:   string(b),
	}
	return ev, ev.Sign(sk)
}

// acceptRoster は受け取った名簿イベントを検査する。cur は現在の名簿（なければ nil）。
// 設定された管理者の署名で、同じネットワーク、版が新しく、未来すぎないものだけ通す。
func acceptRoster(ev *nostr.Event, network string, admins []string, cur *Roster, now time.Time) (*Roster, error) {
	if ev.Kind != KindRoster {
		return nil, fmt.Errorf("kind 違い")
	}
	if !slices.Contains(admins, ev.PubKey) {
		return nil, fmt.Errorf("管理者でない署名者")
	}
	if ok, err := ev.CheckSignature(); !ok || err != nil {
		return nil, fmt.Errorf("署名が不正")
	}
	if ev.Tags.GetD() != network {
		return nil, fmt.Errorf("ネットワーク違い")
	}
	if ev.CreatedAt.Time().After(now.Add(10 * time.Minute)) {
		return nil, fmt.Errorf("時刻が未来すぎる")
	}
	var r Roster
	if err := json.Unmarshal([]byte(ev.Content), &r); err != nil {
		return nil, err
	}
	if r.Network != network {
		return nil, fmt.Errorf("本文のネットワーク違い")
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	if cur != nil && r.Version <= cur.Version {
		return nil, fmt.Errorf("古い版 %d <= %d", r.Version, cur.Version)
	}
	return &r, nil
}
