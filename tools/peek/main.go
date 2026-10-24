package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// 部外者の目で、リレー上の kind 21777 を見る（鍵は持たない）
func main() {
	secrets := os.Args[1:] // 出てきてはいけない文字列
	pool := nostr.NewSimplePool(context.Background(), nostr.WithAuthHandler(func(ctx context.Context, e nostr.RelayEvent) error {
		return e.Event.Sign(nostr.GeneratePrivateKey())
	}))
	ctx, c := context.WithTimeout(context.Background(), 8*time.Second)
	defer c()
	sec := 300
	if v := os.Getenv("SINCE"); v != "" {
		fmt.Sscan(v, &sec)
	}
	since := nostr.Now() - nostr.Timestamp(sec)
	for _, r := range []string{"wss://r.kojira.io", "wss://x.kojira.io", "wss://n.kojira.io"} {
		n, authors, leaks := 0, map[string]bool{}, 0
		for ev := range pool.FetchMany(ctx, []string{r}, nostr.Filter{Kinds: []int{21777, 21779, 31777}, Since: &since}) {
			n++
			authors[ev.PubKey] = true
			b, _ := json.Marshal(ev.Event)
			for _, s := range secrets {
				if strings.Contains(string(b), s) {
					leaks++
				}
			}
			if n == 1 {
				fmt.Printf("  例: kind=%d pubkey=%s… tags=%v content=%s…\n", ev.Kind, ev.PubKey[:12], ev.Tags, ev.Content[:40])
			}
		}
		fmt.Printf("%s: 直近 %d 件、署名鍵 %d 種類、秘密の文字列の出現 %d\n", r, n, len(authors), leaks)
	}
}
