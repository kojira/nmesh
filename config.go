package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/crypto/curve25519"
)

const (
	KindRoster   = 21779 // 名簿（管理者の署名）。リレーには直接出さず、包みの中に入れて運ぶ
	KindAnnounce = 21777 // 外側の包み（エフェメラル）
)

var defaultRelays = []string{"wss://r.kojira.io", "wss://x.kojira.io", "wss://n.kojira.io"}
var defaultStun = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}

type Expose struct {
	Port int    `json:"port"` // メッシュ側で待ち受けるTCPポート
	To   string `json:"to"`   // 転送先（例 127.0.0.1:8790）
}

type Config struct {
	Network    string   `json:"network"`
	Admins     []string `json:"admins"`
	Relays     []string `json:"relays"`
	Stun       []string `json:"stun"`
	ListenPort int      `json:"listen_port"`
	Mode       string   `json:"mode"`        // "userspace" | "tun"
	Socks      string   `json:"socks"`       // userspace: SOCKS5 待ち受け（空なら無効）
	Expose     []Expose `json:"expose"`      // userspace: メッシュから受ける転送
	TunName    string   `json:"tun_name"`    // tun: Linux のインターフェース名
	MTU        int      `json:"mtu"`
	DNS        string   `json:"dns"`         // メッシュ名の DNS 待ち受け（例 127.0.0.1:53053、空なら無効）
	DNSInstall bool     `json:"dns_install"` // OS にこのドメインだけの問い合わせ先として登録する（root が必要）
}

type Keys struct {
	NostrSK string `json:"nostr_sk"`
	WgSK    string `json:"wg_sk"`
}

type State struct {
	Dir  string
	Cfg  Config
	Keys Keys
	Pub  string // nostr 公開鍵 hex
	WgPub string
}

func loadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func saveJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newWgKey() string {
	var k [32]byte
	rand.Read(k[:])
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return hex.EncodeToString(k[:])
}

func wgPublic(skHex string) (string, error) {
	sk, err := hex.DecodeString(skHex)
	if err != nil || len(sk) != 32 {
		return "", fmt.Errorf("bad wg key")
	}
	pk, err := curve25519.X25519(sk, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pk), nil
}

func initState(dir string) (*State, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	kp := filepath.Join(dir, "keys.json")
	if _, err := os.Stat(kp); err == nil {
		return nil, fmt.Errorf("%s は既にあります", kp)
	}
	k := Keys{NostrSK: nostr.GeneratePrivateKey(), WgSK: newWgKey()}
	if err := saveJSON(kp, k, 0600); err != nil {
		return nil, err
	}
	cp := filepath.Join(dir, "config.json")
	if _, err := os.Stat(cp); err != nil {
		c := Config{Relays: defaultRelays, Stun: defaultStun, ListenPort: 41820, Mode: "userspace", Socks: "127.0.0.1:1080", MTU: 1280, TunName: "nmesh0", DNS: "127.0.0.1:53053"}
		if err := saveJSON(cp, c, 0600); err != nil {
			return nil, err
		}
	}
	return loadState(dir)
}

func loadState(dir string) (*State, error) {
	s := &State{Dir: dir}
	if err := loadJSON(filepath.Join(dir, "keys.json"), &s.Keys); err != nil {
		return nil, fmt.Errorf("鍵がありません（nmesh init を先に）: %w", err)
	}
	if err := loadJSON(filepath.Join(dir, "config.json"), &s.Cfg); err != nil {
		return nil, err
	}
	if s.Cfg.MTU == 0 {
		s.Cfg.MTU = 1280
	}
	var err error
	if s.Pub, err = nostr.GetPublicKey(s.Keys.NostrSK); err != nil {
		return nil, err
	}
	if s.WgPub, err = wgPublic(s.Keys.WgSK); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *State) saveConfig() error {
	return saveJSON(filepath.Join(s.Dir, "config.json"), s.Cfg, 0600)
}
