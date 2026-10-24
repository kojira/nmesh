package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func TestChainForwardOnly(t *testing.T) {
	k0 := randKey()
	kf := keyFile{Chains: []chainState{{Gen: 0, T: 100, K: hex.EncodeToString(k0[:])}}}
	advanceChains(&kf, time.Unix(105*60, 0))
	if kf.Chains[0].T != 104 {
		t.Fatal(kf.Chains[0].T)
	}
	k := k0
	for i := 0; i < 4; i++ {
		k = stepKey(k)
	}
	if kf.Chains[0].K != hex.EncodeToString(k[:]) {
		t.Fatal("鎖の進め方が違う")
	}
	if kf.Chains[0].K == hex.EncodeToString(k0[:]) {
		t.Fatal("古い鍵が残っている")
	}
}

func TestOuterRoundTrip(t *testing.T) {
	k := randKey()
	s := slot{gen: 0, t: minuteOf(time.Now()), k: k}
	sk := nostr.GeneratePrivateKey()
	in, _ := signInner(pokeBody{Type: "poke", Net: "n"}, sk)
	ev, err := wrapOuter(envelope{Type: "poke", Ev: in}, s)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := nostr.GetPublicKey(sk)
	if ev.PubKey == pub {
		t.Fatal("外側に本人の鍵が出ている")
	}
	if p := ev.Tags.GetFirst([]string{"p"}); p != nil {
		t.Fatal("p タグがある")
	}
	env, _, err := unwrapOuter(&ev, []slot{s})
	if err != nil || env.Type != "poke" {
		t.Fatal(err)
	}
	var b pokeBody
	from, err := openInner(env.Ev, &b, time.Now())
	if err != nil || from != pub {
		t.Fatal(err)
	}
	other := slot{k: stepKey(k)}
	if _, _, err := unwrapOuter(&ev, []slot{other}); err == nil {
		t.Fatal("別の分の鍵で開いた")
	}
}

func TestSealOneShot(t *testing.T) {
	eph := nostr.GeneratePrivateKey()
	ephPub, _ := nostr.GetPublicKey(eph)
	sk := nostr.GeneratePrivateKey()
	in, _ := signInner(finBody{Type: "fin"}, sk)
	e, ct, ck1, err := sealTo(in, ephPub)
	if err != nil {
		t.Fatal(err)
	}
	got, ck2, err := unseal(ct, e, eph)
	if err != nil || got.ID != in.ID || ck1 != ck2 {
		t.Fatal("開けない")
	}
	// 送り主の長期鍵では開けない（暗号化に長期鍵を使っていない）
	if _, _, err := unseal(ct, e, sk); err == nil {
		t.Fatal("長期鍵で開いた")
	}
}

func TestInviteRoundTrip(t *testing.T) {
	k := randKey()
	iv := invite{V: 1, Net: "abc", Admin: hex.EncodeToString(k[:]), Gen: 2, T: 5, K: hex.EncodeToString(k[:])}
	got, err := parseInvite(iv.String())
	if err != nil || got.Gen != 2 || got.K != iv.K {
		t.Fatal(err)
	}
}
