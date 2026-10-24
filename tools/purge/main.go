package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func main() {
	var k struct{ NostrSK string `json:"nostr_sk"` }
	b, _ := os.ReadFile(os.Args[2])
	json.Unmarshal(b, &k)
	pub, _ := nostr.GetPublicKey(k.NostrSK)
	relays := []string{"wss://r.kojira.io", "wss://x.kojira.io", "wss://n.kojira.io"}
	pool := nostr.NewSimplePool(context.Background(), nostr.WithAuthHandler(func(ctx context.Context, e nostr.RelayEvent) error { return e.Event.Sign(k.NostrSK) }))
	list := func() map[string]*nostr.Event {
		ctx, c := context.WithTimeout(context.Background(), 8*time.Second)
		defer c()
		out := map[string]*nostr.Event{}
		for _, r := range relays {
			n := 0
			for ev := range pool.FetchMany(ctx, []string{r}, nostr.Filter{Authors: []string{pub}}) {
				n++
				out[ev.ID] = ev.Event
				fmt.Printf("  %s kind=%d id=%s d=%s\n", r, ev.Kind, ev.ID[:12], ev.Tags.GetD())
			}
			fmt.Printf("%s: %d 件\n", r, n)
		}
		return out
	}
	evs := list()
	if os.Args[1] != "delete" {
		return
	}
	tags := nostr.Tags{}
	ds := map[string]bool{}
	for id, ev := range evs {
		tags = append(tags, nostr.Tag{"e", id})
		if ev.Kind >= 30000 && ev.Kind < 40000 {
			ds[fmt.Sprintf("%d:%s:%s", ev.Kind, pub, ev.Tags.GetD())] = true
		}
	}
	for a := range ds {
		tags = append(tags, nostr.Tag{"a", a})
	}
	if len(tags) == 0 {
		return
	}
	del := nostr.Event{Kind: 5, CreatedAt: nostr.Now(), Tags: tags}
	del.Sign(k.NostrSK)
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	for r := range pool.PublishMany(ctx, relays, del) {
		fmt.Println("削除依頼", r.RelayURL, r.Error)
	}
	c()
	time.Sleep(2 * time.Second)
	fmt.Println("== 削除後")
	list()
}
