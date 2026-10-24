package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type peer struct {
	pub        string
	name       string
	ip         netip.Addr
	wgPub      string
	cands      []netip.AddrPort
	confirmed  map[netip.AddrPort]time.Time
	endpoint   netip.AddrPort
	punchUntil time.Time
	lastAnn    time.Time
	punchKeys  [][]byte // 直近のやりとりの会話鍵から作る（新しい順、最大4つ）
	handshake  time.Time
	rx, tx     int64
	punchRx    int
}

// 自分が出した問い合わせ（使い捨て鍵）と、答えたときの折り返し待ち
type pendingReq struct {
	sk      string
	expires time.Time
	answered map[string]bool // 答えをくれた相手
}

type pendingFin struct {
	sk      string
	peer    string
	expires time.Time
}

type Mesh struct {
	st     *State
	pool   *nostr.SimplePool
	bind   *udpBind
	stun   *stunClient
	dev    *device.Device
	tunDev tun.Device
	kr     *keyring

	mu        sync.Mutex
	roster    *Roster
	rosterEv  *nostr.Event
	me        *Member
	peers     map[string]*peer // nostr pubkey -> peer
	external  []netip.AddrPort
	port      uint16
	rosterCh  chan struct{}
	reqCh     chan string // 問い合わせを送る理由
	pingFn    func(context.Context, netip.Addr) (time.Duration, error)
	reqs      map[string]*pendingReq // reHash(E_r) -> 
	fins      map[string]*pendingFin // reHash(E_s2) ->
	seen      map[string]time.Time   // 外側イベント ID
	resub     chan struct{}
	stats     struct{ outer, req, resp, fin, poke, sent int }
}

const punchMagic = "NMSHPNCH"

func (m *Mesh) logf(format string, a ...any) { log.Printf(format, a...) }

func newMesh(st *State) *Mesh {
	m := &Mesh{st: st, peers: map[string]*peer{}, rosterCh: make(chan struct{}, 1), reqCh: make(chan string, 4), resub: make(chan struct{}, 1),
		reqs: map[string]*pendingReq{}, fins: map[string]*pendingFin{}, seen: map[string]time.Time{}, kr: &keyring{dir: st.Dir}}
	m.bind = &udpBind{}
	m.stun = newStunClient(m.bind)
	m.bind.onControl = func(b []byte, from netip.AddrPort) bool {
		if m.stun.handle(b) {
			return true
		}
		if len(b) >= len(punchMagic) && string(b[:len(punchMagic)]) == punchMagic {
			m.handlePunch(b, from)
			return true
		}
		return false
	}
	// AUTH には使い捨ての鍵を使う（端末の npub をリレーに知らせない）
	authSK := nostr.GeneratePrivateKey()
	m.pool = nostr.NewSimplePool(context.Background(), nostr.WithAuthHandler(func(ctx context.Context, ev nostr.RelayEvent) error {
		return ev.Event.Sign(authSK)
	}))
	return m
}

// ---- 名簿 ----

func (m *Mesh) rosterPath() string { return filepath.Join(m.st.Dir, "roster-event.json") }

func (m *Mesh) loadCachedRoster() {
	var ev nostr.Event
	if err := loadJSON(m.rosterPath(), &ev); err != nil {
		return
	}
	if r, err := acceptRoster(&ev, m.st.Cfg.Network, m.st.Cfg.Admins, nil, time.Now()); err == nil {
		m.applyRoster(r, &ev)
	}
}

// offerRoster は運ばれてきた名簿を検査し、新しければ適用する。
func (m *Mesh) offerRoster(ev *nostr.Event) bool {
	m.mu.Lock()
	cur := m.roster
	m.mu.Unlock()
	r, err := acceptRoster(ev, m.st.Cfg.Network, m.st.Cfg.Admins, cur, time.Now())
	if err != nil {
		if !strings.HasPrefix(err.Error(), "古い版") {
			m.logf("名簿を拒否: %v", err)
		}
		return false
	}
	saveJSON(m.rosterPath(), ev, 0600)
	m.applyRoster(r, ev)
	return true
}

func (m *Mesh) applyRoster(r *Roster, ev *nostr.Event) {
	m.mu.Lock()
	m.roster = r
	m.rosterEv = ev
	m.me = r.member(m.st.Pub)
	keep := map[string]bool{}
	for _, mem := range r.Members {
		if mem.Pubkey == m.st.Pub || m.me == nil {
			continue // 自分が名簿にないなら誰ともつながらない
		}
		keep[mem.Pubkey] = true
		p := m.peers[mem.Pubkey]
		if p == nil {
			p = &peer{pub: mem.Pubkey, confirmed: map[netip.AddrPort]time.Time{}}
			m.peers[mem.Pubkey] = p
		}
		p.name = mem.Name
		newIP, _ := netip.ParseAddr(mem.IP)
		if p.ip != newIP {
			p.ip = newIP
			if p.wgPub != "" {
				m.ipcPeerLocked(p)
			}
		}
	}
	for pub, p := range m.peers {
		if !keep[pub] {
			m.logf("名簿から外れたので切断: %s", p.name)
			if p.wgPub != "" && m.dev != nil {
				m.dev.IpcSet("public_key=" + p.wgPub + "\nremove=true\n")
			}
			delete(m.peers, pub)
		}
	}
	me := m.me
	m.mu.Unlock()
	if me == nil {
		m.logf("名簿 v%d を受信。ただしこの端末は名簿にありません", r.Version)
	} else {
		m.logf("名簿 v%d を適用: 自分=%s %s、メンバー %d", r.Version, me.Name, me.IP, len(r.Members))
	}
	select {
	case m.rosterCh <- struct{}{}:
	default:
	}
}

func (m *Mesh) isMember(pub string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.roster != nil && m.roster.member(pub) != nil && m.me != nil
}

func (m *Mesh) isAdmin(pub string) bool {
	for _, a := range m.st.Cfg.Admins {
		if a == pub {
			return true
		}
	}
	return false
}

// ---- 送信 ----

func (m *Mesh) publish(ctx context.Context, env envelope, gen int) {
	s, ok := m.kr.sendSlot(gen, time.Now())
	if !ok {
		m.logf("送信用の鍵がありません（世代 %d）", gen)
		return
	}
	ev, err := wrapOuter(env, s)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.seen[ev.ID] = time.Now()
	m.stats.sent++
	m.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ok2 := 0
	var errs []string
	for r := range m.pool.PublishMany(cctx, m.st.Cfg.Relays, ev) {
		if r.Error == nil {
			ok2++
		} else {
			errs = append(errs, r.RelayURL+": "+r.Error.Error())
		}
	}
	if ok2 == 0 {
		m.logf("送信に失敗（%s）: %s", env.Type, strings.Join(errs, "; "))
	}
}

func (m *Mesh) curGen() int {
	c, ok := m.kr.current()
	if !ok {
		return -1
	}
	return c.Gen
}

func (m *Mesh) sendReq(ctx context.Context, gen int) {
	m.mu.Lock()
	rv := int64(0)
	if m.roster != nil {
		rv = m.roster.Version
	}
	m.mu.Unlock()
	sk := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(sk)
	nonce := make([]byte, 8)
	rand.Read(nonce)
	in, err := signInner(reqBody{Type: "req", Net: m.st.Cfg.Network, E: pub, Gen: m.curGen(), RV: rv, TS: time.Now().Unix(), Nonce: hex.EncodeToString(nonce)}, m.st.Keys.NostrSK)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.reqs[reHash(pub)] = &pendingReq{sk: sk, expires: time.Now().Add(msgMaxAge), answered: map[string]bool{}}
	m.mu.Unlock()
	m.publish(ctx, envelope{Type: "req", Ev: in}, gen)
}

func (m *Mesh) sendPoke(ctx context.Context) {
	m.mu.Lock()
	rv := int64(0)
	if m.roster != nil {
		rv = m.roster.Version
	}
	m.mu.Unlock()
	in, err := signInner(pokeBody{Type: "poke", Net: m.st.Cfg.Network, RV: rv, Gen: m.curGen(), TS: time.Now().Unix()}, m.st.Keys.NostrSK)
	if err != nil {
		return
	}
	// 古い世代にも送る（古い世代のまま残っているメンバーが新しい鍵を取りに来られるように）
	m.kr.mu.Lock()
	chains := append([]chainState(nil), m.kr.kf.Chains...)
	m.kr.mu.Unlock()
	for _, c := range chains {
		m.publish(ctx, envelope{Type: "poke", Ev: in}, c.Gen)
	}
}

// ---- 受信 ----

func (m *Mesh) handleOuter(ctx context.Context, ev *nostr.Event) {
	m.mu.Lock()
	if _, dup := m.seen[ev.ID]; dup {
		m.mu.Unlock()
		return
	}
	m.seen[ev.ID] = time.Now()
	m.mu.Unlock()
	if age := time.Since(ev.CreatedAt.Time()); age > msgMaxAge || age < -msgMaxAge {
		return
	}
	env, s, err := unwrapOuter(ev, m.kr.slots(time.Now()))
	if err != nil {
		return
	}
	m.mu.Lock()
	m.stats.outer++
	m.mu.Unlock()
	switch env.Type {
	case "req":
		m.handleReq(ctx, env, s)
	case "resp":
		m.handleResp(ctx, env, s)
	case "fin":
		m.handleFin(env)
	case "poke":
		m.handlePoke(ctx, env, s)
	}
}

func (m *Mesh) handleReq(ctx context.Context, env envelope, s slot) {
	var b reqBody
	from, err := openInner(env.Ev, &b, time.Now())
	if err != nil || b.Type != "req" || b.Net != m.st.Cfg.Network || len(b.E) != 64 || from == m.st.Pub {
		return
	}
	if !m.isMember(from) {
		return // 名簿にない送り主には答えない
	}
	m.mu.Lock()
	m.stats.req++
	m.mu.Unlock()
	// 答える前に少し待つ（一斉に答えないように）
	go func() {
		time.Sleep(time.Duration(mrand.Intn(1500)) * time.Millisecond)
		m.sendResp(ctx, from, b, s)
	}()
}

func (m *Mesh) sendResp(ctx context.Context, to string, req reqBody, s slot) {
	m.mu.Lock()
	var roster *nostr.Event
	if m.roster != nil && req.RV < m.roster.Version {
		roster = m.rosterEv
	}
	m.mu.Unlock()
	if !m.isMember(to) {
		return // 待っている間に名簿から外れた
	}
	var nk *chainState
	if c, ok := m.kr.current(); ok && req.Gen < c.Gen {
		// 相手の世代が古い：今の世代の鍵を渡す（中身は相手の使い捨て鍵宛てに暗号化される）
		nk = &c
	}
	sk2 := nostr.GeneratePrivateKey()
	pub2, _ := nostr.GetPublicKey(sk2)
	body := respBody{Type: "resp", Net: m.st.Cfg.Network, Re: req.E, WG: m.st.WgPub, Cands: m.candidates(), Roster: roster, NetKey: nk, E2: pub2, TS: time.Now().Unix()}
	in, err := signInner(body, m.st.Keys.NostrSK)
	if err != nil {
		return
	}
	e, ct, ck, err := sealTo(in, req.E)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.fins[reHash(pub2)] = &pendingFin{sk: sk2, peer: to, expires: time.Now().Add(msgMaxAge)}
	if p := m.peers[to]; p != nil {
		p.addPunchKey(punchKeyFrom(ck))
	}
	m.mu.Unlock()
	m.publish(ctx, envelope{Type: "resp", Re: reHash(req.E), E: e, CT: ct}, s.gen)
}

func (m *Mesh) handleResp(ctx context.Context, env envelope, s slot) {
	m.mu.Lock()
	pr := m.reqs[env.Re]
	m.mu.Unlock()
	if pr == nil {
		return // 自分宛てではない
	}
	in, ck, err := unseal(env.CT, env.E, pr.sk)
	if err != nil {
		return
	}
	var b respBody
	from, err := openInner(in, &b, time.Now())
	if err != nil || b.Type != "resp" || b.Net != m.st.Cfg.Network {
		return
	}
	myE, _ := nostr.GetPublicKey(pr.sk)
	if b.Re != myE {
		return // 別の問い合わせへの答えを貼り付けたもの
	}
	m.mu.Lock()
	m.stats.resp++
	pr.answered[from] = true
	m.mu.Unlock()
	// 名簿（管理者署名）が付いていれば先に適用する。名簿に載っていない人の答えはその後で判定
	if b.Roster != nil {
		m.offerRoster(b.Roster)
	}
	if b.NetKey != nil && (m.isAdmin(from) || m.isMember(from)) {
		m.acceptNetKey(*b.NetKey, from)
	}
	if !m.isMember(from) {
		return
	}
	m.learnPeer(from, b.WG, b.Cands, punchKeyFrom(ck))
	// 折り返し：自分の住所を、相手の折り返し用の使い捨て鍵宛てに
	fin, err := signInner(finBody{Type: "fin", Net: m.st.Cfg.Network, Re: b.E2, WG: m.st.WgPub, Cands: m.candidates(), TS: time.Now().Unix()}, m.st.Keys.NostrSK)
	if err != nil {
		return
	}
	e, ct, _, err := sealTo(fin, b.E2)
	if err != nil {
		return
	}
	go m.publish(ctx, envelope{Type: "fin", Re: reHash(b.E2), E: e, CT: ct}, s.gen)
}

func (m *Mesh) handleFin(env envelope) {
	m.mu.Lock()
	pf := m.fins[env.Re]
	if pf != nil {
		delete(m.fins, env.Re) // 1回限り
	}
	m.mu.Unlock()
	if pf == nil {
		return
	}
	in, ck, err := unseal(env.CT, env.E, pf.sk)
	if err != nil {
		return
	}
	var b finBody
	from, err := openInner(in, &b, time.Now())
	myE, _ := nostr.GetPublicKey(pf.sk)
	if err != nil || b.Type != "fin" || b.Net != m.st.Cfg.Network || from != pf.peer || b.Re != myE {
		return
	}
	m.mu.Lock()
	m.stats.fin++
	m.mu.Unlock()
	_ = ck
	// ホールパンチ鍵は resp の会話鍵（両者が知っている）を使い続ける
	m.learnPeer(from, b.WG, b.Cands, nil)
}

func (m *Mesh) handlePoke(ctx context.Context, env envelope, s slot) {
	var b pokeBody
	from, err := openInner(env.Ev, &b, time.Now())
	if err != nil || b.Type != "poke" || b.Net != m.st.Cfg.Network || !m.isAdmin(from) {
		return
	}
	m.mu.Lock()
	m.stats.poke++
	rv := int64(0)
	if m.roster != nil {
		rv = m.roster.Version
	}
	m.mu.Unlock()
	if b.RV > rv || b.Gen > m.curGen() {
		m.logf("名簿の更新の合図を受けました（v%d、世代 %d）", b.RV, b.Gen)
		// 合図を受けた世代で問い合わせる（新しい鍵をまだ持っていない場合もそこで届く）
		go m.sendReq(ctx, s.gen)
	}
}

// reload は管理コマンドが書いた名簿と鍵を読み直し、メンバーへ合図を送る。
func (m *Mesh) reload(ctx context.Context) {
	// 名簿を先に適用してから鍵を読む（外した端末へ新しい鍵を渡さないため）
	var ev nostr.Event
	if loadJSON(m.rosterPath(), &ev) == nil {
		m.offerRoster(&ev)
	}
	m.kr.update(time.Now(), nil)
	m.kickResub()
	time.Sleep(500 * time.Millisecond)
	m.sendPoke(ctx)
}

func (m *Mesh) kickResub() {
	select {
	case m.resub <- struct{}{}:
	default:
	}
}

func (m *Mesh) acceptNetKey(c chainState, from string) {
	if _, err := parseKey(c.K); err != nil {
		return
	}
	// 新しい世代の鍵は、管理者から直接か、名簿のメンバー経由で届く
	added := false
	m.kr.update(time.Now(), func(kf *keyFile) error {
		added = addGen(kf, c, time.Now())
		return nil
	})
	if added {
		m.logf("ネットワーク鍵を世代 %d に更新しました", c.Gen)
		m.kickResub()
		select {
		case m.reqCh <- "鍵の更新":
		default:
		}
	}
}

func (m *Mesh) learnPeer(pub, wg string, cs []string, punchKey []byte) {
	if k, err := hex.DecodeString(wg); err != nil || len(k) != 32 {
		return
	}
	var cands []netip.AddrPort
	for _, c := range cs {
		if ap, err := netip.ParseAddrPort(c); err == nil && len(cands) < 16 {
			cands = append(cands, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.peers[pub]
	if p == nil {
		return
	}
	if p.wgPub != wg && p.wgPub != "" && m.dev != nil {
		m.dev.IpcSet("public_key=" + p.wgPub + "\nremove=true\n")
	}
	first := p.wgPub != wg
	p.wgPub = wg
	if punchKey != nil {
		p.addPunchKey(punchKey)
	}
	p.cands = rankCands(cands, m.localPrefixes())
	p.lastAnn = time.Now()
	p.punchUntil = time.Now().Add(20 * time.Second)
	if !p.endpoint.IsValid() && len(p.cands) > 0 {
		p.endpoint = p.cands[0]
	}
	m.ipcPeerLocked(p)
	if first {
		m.logf("相手を登録: %s（候補 %d 件）", p.name, len(p.cands))
	}
}

func (p *peer) addPunchKey(k []byte) {
	p.punchKeys = append([][]byte{k}, p.punchKeys...)
	if len(p.punchKeys) > 4 {
		p.punchKeys = p.punchKeys[:4]
	}
}

// ---- ホールパンチ ----
// 形式: magic(8) | type(1: ping, 2: pong) | 鍵ID(8) | nonce(8) | hmac(16)
// 鍵はそのやりとり限りの会話鍵から作る。鍵IDも同じ鍵から作るので、npub は載らない。

const punchLen = 8 + 1 + 8 + 8 + 16

func punchID(k []byte) []byte { h := sha256.Sum256(append([]byte("nmesh/punch-id"), k...)); return h[:8] }

func (m *Mesh) punchPacket(typ byte, k []byte, nonce []byte) []byte {
	b := make([]byte, 0, punchLen)
	b = append(b, punchMagic...)
	b = append(b, typ)
	b = append(b, punchID(k)...)
	b = append(b, nonce...)
	mac := hmac.New(sha256.New, k)
	mac.Write(b)
	return append(b, mac.Sum(nil)[:16]...)
}

func (m *Mesh) handlePunch(b []byte, from netip.AddrPort) {
	if len(b) != punchLen {
		return
	}
	id := b[9:17]
	m.mu.Lock()
	var p *peer
	var key []byte
	for _, q := range m.peers {
		for _, k := range q.punchKeys {
			if hmac.Equal(punchID(k), id) {
				p, key = q, k
			}
		}
	}
	if p == nil {
		m.mu.Unlock()
		return
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b[:punchLen-16])
	if !hmac.Equal(mac.Sum(nil)[:16], b[punchLen-16:]) {
		m.mu.Unlock()
		return
	}
	typ := b[8]
	p.punchRx++
	_, known := p.confirmed[from]
	p.confirmed[from] = time.Now()
	nonce := append([]byte(nil), b[17:25]...)
	if !known {
		best := m.bestConfirmedLocked(p)
		if best.IsValid() && best != p.endpoint {
			p.endpoint = best
			m.ipcPeerLocked(p)
			m.logf("直接つながる住所を確認: %s → %s", p.name, p.endpoint)
		}
	}
	var reply []byte
	if typ == 1 {
		reply = m.punchPacket(2, key, nonce)
		if time.Now().After(p.punchUntil) {
			p.punchUntil = time.Now().Add(10 * time.Second)
		}
	}
	m.mu.Unlock()
	if reply != nil {
		m.bind.SendRaw(reply, from)
	}
}

func (m *Mesh) punchLoop(ctx context.Context) {
	t := time.NewTicker(700 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		type job struct {
			pkt []byte
			to  []netip.AddrPort
		}
		var jobs []job
		m.mu.Lock()
		for _, p := range m.peers {
			if time.Now().After(p.punchUntil) || len(p.cands) == 0 || len(p.punchKeys) == 0 {
				continue
			}
			nonce := make([]byte, 8)
			rand.Read(nonce)
			jobs = append(jobs, job{m.punchPacket(1, p.punchKeys[0], nonce), append([]netip.AddrPort(nil), p.cands...)})
		}
		m.mu.Unlock()
		for _, j := range jobs {
			for _, to := range j.to {
				m.bind.SendRaw(j.pkt, to)
			}
		}
	}
}

// gc は期限切れの使い捨て鍵を消す。
func (m *Mesh) gc() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, r := range m.reqs {
		if now.After(r.expires) {
			r.sk = ""
			delete(m.reqs, k)
		}
	}
	for k, f := range m.fins {
		if now.After(f.expires) {
			f.sk = ""
			delete(m.fins, k)
		}
	}
	for k, t := range m.seen {
		if now.Sub(t) > 10*time.Minute {
			delete(m.seen, k)
		}
	}
}

// needReq は WireGuard の応答が途絶えた相手がいるか。
func (m *Mesh) staleCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, p := range m.peers {
		if p.handshake.IsZero() || time.Since(p.handshake) > 3*time.Minute {
			n++
		}
	}
	return n
}

func (m *Mesh) ipcPeerLocked(p *peer) {
	if m.dev == nil || p.wgPub == "" || !p.ip.IsValid() {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n", p.wgPub, p.ip)
	if p.endpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", p.endpoint)
	}
	if err := m.dev.IpcSet(b.String()); err != nil {
		m.logf("wg 設定失敗 %s: %v", p.name, err)
	}
}

func (m *Mesh) candidates() []string {
	m.mu.Lock()
	port := m.port
	ext := append([]netip.AddrPort(nil), m.external...)
	var meshPfx netip.Prefix
	if m.roster != nil {
		meshPfx, _ = netip.ParsePrefix(m.roster.CIDR)
	}
	m.mu.Unlock()
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	tsv6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	var out []string
	seen := map[string]bool{}
	add := func(ap netip.AddrPort) {
		s := ap.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if port == 0 {
		return nil
	}
	for _, ap := range ext {
		add(ap)
	}
	src6 := defaultSrc6()
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() || cgnat.Contains(ip) || tsv6.Contains(ip) || (meshPfx.IsValid() && meshPfx.Contains(ip)) {
				continue
			}
			if ip.Is6() && (!ip.IsGlobalUnicast() || (ip.IsGlobalUnicast() && !ip.IsPrivate() && ip != src6)) {
				// IPv6 は「外へ出るときの送り元」だけを載せる。一時アドレスが多数あると、
				// 受けたアドレスと返信の送り元が食い違い、相手側のルーターに捨てられるため。
				continue
			}
			add(netip.AddrPortFrom(ip, port))
		}
	}
	return out
}

// defaultSrc6 は外向き IPv6 の送り元アドレス（パケットは送らない）。
func defaultSrc6() netip.Addr {
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return netip.Addr{}
	}
	defer c.Close()
	ap, _ := netip.ParseAddrPort(c.LocalAddr().String())
	return ap.Addr()
}

func (m *Mesh) localPrefixes() []netip.Prefix {
	var out []netip.Prefix
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				ip, ok1 := netip.AddrFromSlice(ipn.IP)
				ones, _ := ipn.Mask.Size()
				if ok1 {
					out = append(out, netip.PrefixFrom(ip.Unmap(), ones).Masked())
				}
			}
		}
	}
	return out
}

// rankCands: 同じLAN > その他プライベート > IPv6 グローバル > パブリック IPv4
func rankCands(c []netip.AddrPort, local []netip.Prefix) []netip.AddrPort {
	rank := func(ap netip.AddrPort) int {
		a := ap.Addr()
		for _, p := range local {
			if p.Bits() > 0 && p.Contains(a) {
				return 0
			}
		}
		if a.IsPrivate() {
			return 1
		}
		if a.Is6() {
			return 2
		}
		return 3
	}
	out := append([]netip.AddrPort(nil), c...)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

func (m *Mesh) bestConfirmedLocked(p *peer) netip.AddrPort {
	var list []netip.AddrPort
	for ap, t := range p.confirmed {
		if time.Since(t) < 2*time.Minute {
			list = append(list, ap)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].String() < list[j].String() })
	list = rankCands(list, m.localPrefixes())
	if len(list) == 0 {
		return netip.AddrPort{}
	}
	return list[0]
}

// ---- 状態 ----

func (m *Mesh) refreshStats() {
	if m.dev == nil {
		return
	}
	s, err := m.dev.IpcGet()
	if err != nil {
		return
	}
	byWg := map[string]*peer{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.peers {
		if p.wgPub != "" {
			byWg[p.wgPub] = p
		}
	}
	var cur *peer
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "public_key":
			cur = byWg[v]
		case "last_handshake_time_sec":
			if cur != nil {
				n, _ := strconv.ParseInt(v, 10, 64)
				if n > 0 {
					cur.handshake = time.Unix(n, 0)
				}
			}
		case "rx_bytes":
			if cur != nil {
				cur.rx, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.tx, _ = strconv.ParseInt(v, 10, 64)
			}
		case "endpoint":
			if cur != nil {
				if ap, err := netip.ParseAddrPort(v); err == nil {
					cur.endpoint = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
				}
			}
		}
	}
}

type peerStatus struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Pubkey    string `json:"pubkey"`
	State     string `json:"state"`
	Endpoint  string `json:"endpoint,omitempty"`
	Handshake string `json:"last_handshake,omitempty"`
	PunchRx   int    `json:"punch_rx"`
	Cands     int    `json:"cands"`
	Rx        int64  `json:"rx_bytes"`
	Tx        int64  `json:"tx_bytes"`
}

type status struct {
	Updated  string       `json:"updated"`
	Network  string       `json:"network"`
	Roster   int64        `json:"roster_version"`
	Me       *Member      `json:"me"`
	Mode     string       `json:"mode"`
	Port     uint16       `json:"listen_port"`
	External []string     `json:"external"`
	Peers    []peerStatus `json:"peers"`
}

func (m *Mesh) writeStatus() {
	m.refreshStats()
	m.mu.Lock()
	s := status{Updated: time.Now().Format(time.RFC3339), Network: m.st.Cfg.Network, Me: m.me, Mode: m.st.Cfg.Mode, Port: m.port}
	if m.roster != nil {
		s.Roster = m.roster.Version
	}
	for _, e := range m.external {
		s.External = append(s.External, e.String())
	}
	for _, p := range m.peers {
		ps := peerStatus{Name: p.name, IP: p.ip.String(), Pubkey: p.pub, Rx: p.rx, Tx: p.tx, PunchRx: p.punchRx, Cands: len(p.cands)}
		switch {
		case p.wgPub == "":
			ps.State = "告知待ち"
		case !p.handshake.IsZero() && time.Since(p.handshake) < 3*time.Minute:
			ps.State = "接続中"
		case len(p.confirmed) == 0 && !p.lastAnn.IsZero() && time.Now().After(p.punchUntil):
			ps.State = "直接接続できません"
		default:
			ps.State = "接続を試行中"
		}
		if p.endpoint.IsValid() {
			ps.Endpoint = p.endpoint.String()
		}
		if !p.handshake.IsZero() {
			ps.Handshake = p.handshake.Format(time.RFC3339)
		}
		s.Peers = append(s.Peers, ps)
	}
	m.mu.Unlock()
	sort.Slice(s.Peers, func(i, j int) bool { return s.Peers[i].Name < s.Peers[j].Name })
	saveJSON(filepath.Join(m.st.Dir, "status.json"), s, 0644)
}


// ---- 実行 ----

func (m *Mesh) subscribe(ctx context.Context) {
	// 外側の目印は毎分変わるので、分が変わるたびに購読を張り直す
	for {
		now := time.Now()
		var tags []string
		for _, s := range m.kr.slots(now) {
			tags = append(tags, tagOf(s.k))
		}
		next := time.Unix((minuteOf(now)+1)*60, 0).Add(time.Duration(mrand.Intn(3000)) * time.Millisecond)
		sctx, cancel := context.WithDeadline(ctx, next)
		since := nostr.Now() - 120
		f := nostr.Filter{Kinds: []int{KindAnnounce}, Tags: nostr.TagMap{"t": tags}, Since: &since}
		ch := m.pool.SubscribeMany(sctx, m.st.Cfg.Relays, f)
	loop:
		for {
			select {
			case ev, ok := <-ch:
				if !ok {
					break loop
				}
				m.handleOuter(ctx, ev.Event)
			case <-m.resub:
				break loop
			}
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		m.kr.update(time.Now(), nil) // 鎖を進めて古い鍵を消す
	}
}

func (m *Mesh) Run(ctx context.Context, mk func(m *Mesh, me *Member) (tun.Device, error)) error {
	cfg := m.st.Cfg
	if cfg.Network == "" || len(cfg.Admins) == 0 {
		return fmt.Errorf("ネットワーク未設定（nmesh join か nmesh admin create を先に）")
	}
	if err := m.kr.update(time.Now(), nil); err != nil {
		return err
	}
	if _, ok := m.kr.current(); !ok {
		return fmt.Errorf("ネットワーク鍵がありません（招待文字列で join してください）")
	}
	m.mu.Lock()
	m.port = uint16(cfg.ListenPort)
	m.mu.Unlock()
	m.loadCachedRoster()
	go m.subscribe(ctx)

	// 名簿に自分が載るまで、問い合わせを送って待つ
	m.logf("名簿を待っています（自分=%s）", npub(m.st.Pub))
	backoff := []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 60 * time.Second}
	for i := 0; ; i++ {
		m.mu.Lock()
		me := m.me
		m.mu.Unlock()
		if me != nil {
			break
		}
		go m.sendReq(ctx, m.curGen())
		d := 5 * time.Minute
		if i < len(backoff) {
			d = backoff[i]
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.rosterCh:
		case <-time.After(d):
		}
	}

	m.mu.Lock()
	me := *m.me
	m.mu.Unlock()
	td, err := mk(m, &me)
	if err != nil {
		return err
	}
	m.tunDev = td
	m.dev = device.NewDevice(td, m.bind, device.NewLogger(device.LogLevelError, "wg: "))
	if err := m.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", m.st.Keys.WgSK, cfg.ListenPort)); err != nil {
		return fmt.Errorf("WireGuard 起動失敗（UDP %d が使用中？）: %w", cfg.ListenPort, err)
	}
	if err := m.dev.Up(); err != nil {
		return err
	}
	defer m.dev.Close()
	m.mu.Lock()
	m.port = uint16(cfg.ListenPort)
	for _, p := range m.peers {
		m.ipcPeerLocked(p)
	}
	m.mu.Unlock()
	m.logf("WireGuard 起動: UDP %d、メッシュIP %s", cfg.ListenPort, me.IP)
	go m.punchLoop(ctx)

	refreshExternal := func() {
		ext := m.stun.query(cfg.Stun, 3*time.Second)
		m.mu.Lock()
		old := fmt.Sprint(m.external)
		m.external = ext
		m.mu.Unlock()
		if fmt.Sprint(ext) != old {
			m.logf("外から見えた住所: %v", ext)
		}
	}
	refreshExternal()
	lastCands := strings.Join(m.candidates(), ",")

	// 問い合わせ：起動時・ネットワーク変化・途絶・合図・鍵更新のときだけ
	var retry []time.Duration
	var nextReq time.Time
	trigger := func(why string) {
		m.logf("問い合わせを送ります（%s）", why)
		retry = []time.Duration{5 * time.Second, 15 * time.Second, 60 * time.Second}
		nextReq = time.Now()
	}
	trigger("起動")

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastNetCheck, lastStun, lastStatus := time.Now(), time.Now(), time.Time{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.rosterCh:
		case why := <-m.reqCh:
			trigger(why)
		case <-tick.C:
		}
		now := time.Now()
		if !nextReq.IsZero() && now.After(nextReq) {
			go m.sendReq(ctx, m.curGen())
			switch {
			case len(retry) > 0:
				nextReq = now.Add(retry[0])
				retry = retry[1:]
			default:
				nextReq = time.Time{}
			}
		}
		if now.Sub(lastStatus) >= 5*time.Second {
			lastStatus = now
			m.writeStatus()
			m.gc()
			// 全員とつながっていれば、残りの送り直しはやめる
			if m.staleCount() == 0 {
				retry, nextReq = nil, time.Time{}
			} else if nextReq.IsZero() && len(m.peers) > 0 {
				// 途絶えた相手がいる：5分ごとに問い合わせる
				nextReq = now.Add(5 * time.Minute)
			}
		}
		if now.Sub(lastNetCheck) >= 5*time.Second {
			lastNetCheck = now
			if c := strings.Join(m.candidates(), ","); c != lastCands {
				refreshExternal()
				lastCands = strings.Join(m.candidates(), ",")
				trigger("ネットワークの変化")
			}
		}
		if now.Sub(lastStun) >= 5*time.Minute {
			lastStun = now
			refreshExternal()
			if c := strings.Join(m.candidates(), ","); c != lastCands {
				lastCands = c
				trigger("外側の住所の変化")
			}
		}
	}
}

var _ = json.Marshal
var _ = bufio.NewScanner
var _ = strconv.Itoa
var _ = sort.Strings
var _ = filepath.Join
var _ = net.Interfaces
