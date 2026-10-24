package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

		"github.com/nbd-wtf/go-nostr/nip19"
)

const usage = `nmesh — Nostr で見つけ合う WireGuard メッシュ VPN

使い方: nmesh [--dir 状態ディレクトリ] <コマンド>

  init                         この端末の鍵を作る（公開鍵を表示）
  id                           この端末の公開鍵を表示
  admin create <端末名> [--cidr 10.77.0.0/16] [--domain mesh]
                               新しいネットワークを作り、自分を管理者・メンバーにする
  admin add <npub|hex> <端末名> 名簿に追加し、招待文字列を表示（鍵を新しい世代に）
  admin remove <端末名>         名簿から外す（鍵を新しい世代に）
  admin show                   名簿を表示
  join <招待文字列>              admin add が出した招待で参加する
  up [--mode userspace|tun]    起動（userspace は root 不要、tun は root 必要）
  status                       接続状態
  ping <端末名|IP>              メッシュ内へ ping（userspace のとき）
`

func defaultDir() string {
	if d := os.Getenv("NMESH_DIR"); d != "" {
		return d
	}
	if os.Geteuid() == 0 {
		if runtime.GOOS == "darwin" {
			return "/Library/Application Support/nmesh"
		}
		return "/var/lib/nmesh"
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".nmesh")
}

func main() {
	log.SetFlags(log.Ltime)
	gf := flag.NewFlagSet("nmesh", flag.ExitOnError)
	dir := gf.String("dir", defaultDir(), "状態ディレクトリ")
	gf.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	gf.Parse(os.Args[1:])
	args := gf.Args()
	if len(args) == 0 {
		gf.Usage()
		os.Exit(2)
	}
	if err := run(*dir, args); err != nil {
		fmt.Fprintln(os.Stderr, "エラー:", err)
		os.Exit(1)
	}
}

func decodePub(s string) (string, error) {
	if strings.HasPrefix(s, "npub1") {
		_, v, err := nip19.Decode(s)
		if err != nil {
			return "", err
		}
		return v.(string), nil
	}
	if len(s) == 64 {
		return strings.ToLower(s), nil
	}
	return "", fmt.Errorf("公開鍵の形式が不正: %s", s)
}

func npub(hex string) string { s, _ := nip19.EncodePublicKey(hex); return s }

func run(dir string, args []string) error {
	switch args[0] {
	case "init":
		st, err := initState(dir)
		if err != nil {
			return err
		}
		fmt.Printf("鍵を作りました: %s\n公開鍵: %s\n", dir, npub(st.Pub))
		return nil
	case "id":
		st, err := loadState(dir)
		if err != nil {
			return err
		}
		fmt.Println(npub(st.Pub))
		return nil
	case "admin":
		return adminCmd(dir, args[1:])
	case "join":
		if len(args) != 2 {
			return errors.New("nmesh join <招待文字列>")
		}
		st, err := loadState(dir)
		if err != nil {
			return err
		}
		iv, err := parseInvite(args[1])
		if err != nil {
			return err
		}
		if iv.For != "" && iv.For != st.Pub {
			return errors.New("この招待は別の端末向けです")
		}
		st.Cfg.Network, st.Cfg.Admins = iv.Net, []string{iv.Admin}
		if len(iv.Relays) > 0 {
			st.Cfg.Relays = iv.Relays
		}
		kr := &keyring{dir: dir}
		if err := kr.update(time.Now(), func(kf *keyFile) error {
			if !addGen(kf, chainState{Gen: iv.Gen, T: iv.T, K: iv.K}, time.Now()) {
				return errors.New("この招待より新しい鍵を既に持っています")
			}
			return nil
		}); err != nil {
			return err
		}
		if err := st.saveConfig(); err != nil {
			return err
		}
		fmt.Println("参加の設定をしました。nmesh up で起動してください。")
		return nil
	case "up":
		fs := flag.NewFlagSet("up", flag.ExitOnError)
		mode := fs.String("mode", "", "userspace | tun")
		fs.Parse(args[1:])
		st, err := loadState(dir)
		if err != nil {
			return err
		}
		if *mode != "" {
			st.Cfg.Mode = *mode
		}
		return up(st)
	case "status":
		var s status
		if err := loadJSON(filepath.Join(dir, "status.json"), &s); err != nil {
			return fmt.Errorf("状態がありません（起動していない？）: %w", err)
		}
		t, _ := time.Parse(time.RFC3339, s.Updated)
		if time.Since(t) > 30*time.Second {
			fmt.Printf("※ 最終更新 %s（デーモンが止まっている可能性）\n", s.Updated)
		}
		me := "-"
		if s.Me != nil {
			me = s.Me.Name + " " + s.Me.IP
		}
		fmt.Printf("ネットワーク %s（名簿 v%d）  自分: %s  モード: %s  UDP %d\n外から見えた住所: %s\n\n", s.Network, s.Roster, me, s.Mode, s.Port, strings.Join(s.External, ", "))
		for _, p := range s.Peers {
			fmt.Printf("%-16s %-12s %-18s %-30s rx %d / tx %d\n", p.Name, p.IP, p.State, p.Endpoint, p.Rx, p.Tx)
		}
		return nil
	case "ping":
		if len(args) != 2 {
			return errors.New("nmesh ping <端末名|IP>")
		}
		c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", filepath.Join(dir, "ctl.sock"))
		}}, Timeout: 30 * time.Second}
		for i := 0; i < 4; i++ {
			r, err := c.Get("http://nmesh/ping?to=" + args[1])
			if err != nil {
				return fmt.Errorf("デーモンに接続できません: %w", err)
			}
			var out struct{ IP, RTT, Err string }
			json.NewDecoder(r.Body).Decode(&out)
			r.Body.Close()
			if out.Err != "" {
				fmt.Printf("%s: %s\n", args[1], out.Err)
			} else {
				fmt.Printf("%s (%s): %s\n", args[1], out.IP, out.RTT)
			}
			time.Sleep(time.Second)
		}
		return nil
	}
	fmt.Fprint(os.Stderr, usage)
	return fmt.Errorf("不明なコマンド: %s", args[0])
}

func up(st *State) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	m := newMesh(st)
	var mk = userspaceMode(ctx)
	switch st.Cfg.Mode {
	case "userspace", "":
	case "tun":
		mk = tunMode
	default:
		return fmt.Errorf("不明なモード: %s", st.Cfg.Mode)
	}
	sock := filepath.Join(st.Dir, "ctl.sock")
	os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	os.Chmod(sock, 0600)
	defer os.Remove(sock)
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]string{}
		to := r.URL.Query().Get("to")
		ip, ok := m.resolve(to)
		switch {
		case !ok || !m.inMesh(ip):
			out["Err"] = "メッシュ内の端末ではありません"
		case m.pingFn == nil:
			out["Err"] = "TUN モードでは OS の ping を使ってください"
		default:
			out["IP"] = ip.String()
			c, cc := context.WithTimeout(r.Context(), 3*time.Second)
			d, err := m.pingFn(c, ip)
			cc()
			if err != nil {
				out["Err"] = "応答なし: " + err.Error()
			} else {
				out["RTT"] = d.Round(100 * time.Microsecond).String()
			}
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", 405)
			return
		}
		m.reload(r.Context())
		w.Write([]byte("ok"))
	})
	go http.Serve(l, mux)
	return m.Run(ctx, mk)
}

// ---- 管理者 ----

func adminCmd(dir string, args []string) error {
	if len(args) == 0 {
		return errors.New("nmesh admin create|add|remove|show")
	}
	st, err := loadState(dir)
	if err != nil {
		return err
	}
	rp := filepath.Join(dir, "admin-roster.json")
	var r Roster
	if args[0] != "create" {
		if err := loadJSON(rp, &r); err != nil {
			return fmt.Errorf("この端末は管理者ではありません（admin create 未実行）")
		}
	}
	switch args[0] {
	case "create":
		if _, err := os.Stat(rp); err == nil {
			return fmt.Errorf("既に作成済み: %s", rp)
		}
		fs := flag.NewFlagSet("create", flag.ExitOnError)
		cidr := fs.String("cidr", "10.77.0.0/16", "メッシュのアドレス範囲")
		domain := fs.String("domain", "mesh", "名前のドメイン")
		name := fs.String("name", "", "ネットワーク名")
		var pos []string
		rest := args[1:]
		for len(rest) > 0 {
			fs.Parse(rest)
			rest = fs.Args()
			if len(rest) > 0 {
				pos = append(pos, rest[0])
				rest = rest[1:]
			}
		}
		if len(pos) != 1 {
			return errors.New("nmesh admin create <この端末の名前> [--name ネットワーク名]")
		}
		r = Roster{Network: newNetworkID(), Name: *name, CIDR: *cidr, Domain: *domain, Admins: []string{st.Pub}}
		ip, err := r.nextIP()
		if err != nil {
			return err
		}
		r.Members = []Member{{Pubkey: st.Pub, Name: pos[0], IP: ip.String()}}
		st.Cfg.Network, st.Cfg.Admins = r.Network, []string{st.Pub}
		if err := st.saveConfig(); err != nil {
			return err
		}
	case "add":
		if len(args) != 3 {
			return errors.New("nmesh admin add <npub|hex> <端末名>")
		}
		pub, err := decodePub(args[1])
		if err != nil {
			return err
		}
		if r.member(pub) != nil || r.byName(args[2]) != nil {
			return fmt.Errorf("既に名簿にあります")
		}
		ip, err := r.nextIP()
		if err != nil {
			return err
		}
		r.Members = append(r.Members, Member{Pubkey: pub, Name: args[2], IP: ip.String()})
	case "remove":
		if len(args) != 2 {
			return errors.New("nmesh admin remove <端末名>")
		}
		mem := r.byName(args[1])
		if mem == nil {
			return fmt.Errorf("見つかりません: %s", args[1])
		}
		if mem.Pubkey == st.Pub {
			return fmt.Errorf("自分は外せません")
		}
		var keep []Member
		for _, x := range r.Members {
			if x.Pubkey != mem.Pubkey {
				keep = append(keep, x)
			}
		}
		r.Members = keep
	case "show":
		gen := -1
		kr := &keyring{dir: dir}
		if kr.update(time.Now(), nil) == nil {
			if c, ok := kr.current(); ok {
				gen = c.Gen
			}
		}
		fmt.Printf("ネットワークID: %s  名前: %s  範囲: %s  ドメイン: %s  版: %d  鍵の世代: %d\n管理者: %s\n", r.Network, r.Name, r.CIDR, r.Domain, r.Version, gen, npub(r.Admins[0]))
		for _, x := range r.Members {
			fmt.Printf("  %-16s %-14s %s\n", x.Name, x.IP, npub(x.Pubkey))
		}
		return nil
	default:
		return fmt.Errorf("不明: admin %s", args[0])
	}
	r.Version = time.Now().UnixMilli()
	ev, err := r.sign(st.Keys.NostrSK)
	if err != nil {
		return err
	}
	// 出入りがあればネットワーク鍵を新しい世代にする（外された端末は新しい鍵を受け取れない）
	kr := &keyring{dir: dir}
	var newGen chainState
	if err := kr.update(time.Now(), func(kf *keyFile) error {
		g := 0
		for _, c := range kf.Chains {
			if c.Gen >= g {
				g = c.Gen + 1
			}
		}
		k := randKey()
		newGen = chainState{Gen: g, T: minuteOf(time.Now()) - 1, K: hex.EncodeToString(k[:])}
		addGen(kf, newGen, time.Now())
		return nil
	}); err != nil {
		return err
	}
	if err := saveJSON(rp, r, 0600); err != nil {
		return err
	}
	if err := saveJSON(filepath.Join(dir, "roster-event.json"), ev, 0600); err != nil {
		return err
	}
	fmt.Printf("名簿 v%d を保存しました（メンバー %d、ネットワーク鍵 世代 %d）\n", r.Version, len(r.Members), newGen.Gen)
	if args[0] == "add" {
		cur, _ := kr.current()
		pub, _ := decodePub(args[1])
		iv := invite{V: 1, Net: r.Network, Admin: st.Pub, For: pub, Relays: st.Cfg.Relays, Gen: cur.Gen, T: cur.T, K: cur.K}
		fmt.Printf("\n追加する端末で、次を実行してください（Nostr を通さず、安全な方法で渡してください）:\n  nmesh join %s\n\n", iv)
	}
	// 起動中のデーモンに知らせる（デーモンがほかのメンバーへ合図を送る）
	c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", filepath.Join(dir, "ctl.sock"))
	}}, Timeout: 20 * time.Second}
	if resp, err := c.Post("http://nmesh/reload", "", nil); err == nil {
		resp.Body.Close()
		fmt.Println("起動中のデーモンに反映し、メンバーへ更新の合図を送りました。")
	} else if args[0] != "create" {
		fmt.Println("デーモンが起動していません。nmesh up すると、メンバーへ更新が届きます。")
	}
	_ = netip.Addr{}
	return nil
}
