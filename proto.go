package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// 外側：kind 21777、タグ ["t", 目印]、中身は分ごとのネットワーク鍵で NIP-44、使い捨て鍵で署名。
// 内側（envelope）：
//   req  … 送り主が署名した reqBody（全メンバーが読める。住所は入れない）
//   resp … re=SHA256(E_r)、e=答える側の1回限りの公開鍵、ct=ECDH(e, E_r) で暗号化した「署名付き respBody」
//   fin  … re=SHA256(E_s2)、e=1回限りの公開鍵、ct=ECDH(e, E_s2) で暗号化した「署名付き finBody」
//   poke … 管理者が署名した pokeBody

const innerKind = 21778 // 内側の署名イベント用（リレーには出さない）

type envelope struct {
	Type string       `json:"type"`
	Ev   *nostr.Event `json:"ev,omitempty"`
	Re   string       `json:"re,omitempty"`
	E    string       `json:"e,omitempty"`
	CT   string       `json:"ct,omitempty"`
}

type reqBody struct {
	Type  string `json:"type"` // "req"
	Net   string `json:"net"`
	E     string `json:"e"` // 使い捨ての公開鍵 E_r
	Gen   int    `json:"gen"`
	RV    int64  `json:"rv"`
	TS    int64  `json:"ts"`
	Nonce string `json:"n"`
}

type respBody struct {
	Type   string       `json:"type"` // "resp"
	Net    string       `json:"net"`
	Re     string       `json:"re"` // 答える相手の E_r
	WG     string       `json:"wg"`
	Cands  []string     `json:"c"`
	Roster *nostr.Event `json:"roster,omitempty"`
	NetKey *chainState  `json:"nk,omitempty"`
	E2     string       `json:"e2"` // 折り返し用の使い捨て公開鍵
	TS     int64        `json:"ts"`
}

type finBody struct {
	Type  string   `json:"type"` // "fin"
	Net   string   `json:"net"`
	Re    string   `json:"re"` // E_s2
	WG    string   `json:"wg"`
	Cands []string `json:"c"`
	TS    int64    `json:"ts"`
}

type pokeBody struct {
	Type string `json:"type"` // "poke"
	Net  string `json:"net"`
	RV   int64  `json:"rv"`
	Gen  int    `json:"gen"`
	TS   int64  `json:"ts"`
}

const msgMaxAge = 2 * time.Minute

func reHash(pub string) string { h := sha256.Sum256([]byte("nmesh/re" + pub)); return hex.EncodeToString(h[:16]) }

func signInner(body any, sk string) (*nostr.Event, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ev := &nostr.Event{Kind: innerKind, CreatedAt: nostr.Now(), Content: string(b)}
	return ev, ev.Sign(sk)
}

// openInner は内側の署名を確かめ、本文を v に読み、署名者を返す。
func openInner(ev *nostr.Event, v any, now time.Time) (string, error) {
	if ev == nil || ev.Kind != innerKind {
		return "", fmt.Errorf("内側の形式が不正")
	}
	if ok, err := ev.CheckSignature(); !ok || err != nil {
		return "", fmt.Errorf("署名が不正")
	}
	age := now.Sub(ev.CreatedAt.Time())
	if age > msgMaxAge || age < -msgMaxAge {
		return "", fmt.Errorf("古すぎるか未来")
	}
	return ev.PubKey, json.Unmarshal([]byte(ev.Content), v)
}

// sealTo は1回限りの鍵で相手の使い捨て公開鍵宛てに暗号化する。
// 戻り値：自分の1回限りの公開鍵、暗号文、会話鍵（ホールパンチ鍵を作るため）
func sealTo(inner *nostr.Event, peerEph string) (string, string, [32]byte, error) {
	sk := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(sk)
	ck, err := nip44.GenerateConversationKey(peerEph, sk)
	if err != nil {
		return "", "", ck, err
	}
	b, _ := json.Marshal(inner)
	ct, err := nip44.Encrypt(string(b), ck)
	return pub, ct, ck, err
}

func unseal(ct, senderEph, mySK string) (*nostr.Event, [32]byte, error) {
	ck, err := nip44.GenerateConversationKey(senderEph, mySK)
	if err != nil {
		return nil, ck, err
	}
	pt, err := nip44.Decrypt(ct, ck)
	if err != nil {
		return nil, ck, err
	}
	var ev nostr.Event
	if err := json.Unmarshal([]byte(pt), &ev); err != nil {
		return nil, ck, err
	}
	return &ev, ck, nil
}

func punchKeyFrom(ck [32]byte) []byte {
	h := sha256.Sum256(append([]byte("nmesh/punch"), ck[:]...))
	return h[:]
}

// wrapOuter は外側の包みを作る。
func wrapOuter(env envelope, s slot) (nostr.Event, error) {
	b, _ := json.Marshal(env)
	ct, err := nip44.Encrypt(string(b), encOf(s.k))
	if err != nil {
		return nostr.Event{}, err
	}
	ev := nostr.Event{Kind: KindAnnounce, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"t", tagOf(s.k)}}, Content: ct}
	return ev, ev.Sign(nostr.GeneratePrivateKey())
}

func unwrapOuter(ev *nostr.Event, slots []slot) (envelope, slot, error) {
	var env envelope
	t := ev.Tags.GetFirst([]string{"t"})
	if t == nil || len(*t) < 2 {
		return env, slot{}, fmt.Errorf("目印なし")
	}
	for _, s := range slots {
		if tagOf(s.k) != (*t)[1] {
			continue
		}
		if ok, err := ev.CheckSignature(); !ok || err != nil {
			return env, s, fmt.Errorf("外側の署名が不正")
		}
		pt, err := nip44.Decrypt(ev.Content, encOf(s.k))
		if err != nil {
			return env, s, err
		}
		return env, s, json.Unmarshal([]byte(pt), &env)
	}
	return env, slot{}, fmt.Errorf("知らない目印")
}
