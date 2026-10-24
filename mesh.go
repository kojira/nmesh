package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// 告知の中身（NIP-44 で相手ごとに暗号化）
type announce struct {
	Network string   `json:"net"`
	WgPub   string   `json:"wg"`
	Cands   []string `json:"c"`
	TS      int64    `json:"ts"`
	Reply   bool     `json:"r,omitempty"` // 返信として送ったもの（返信には返信しない）
}

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
	lastReply  time.Time
	punchKey   []byte
	convKey    [32]byte
	handshake  time.Time
	rx, tx     int64
	punchRx    int
}

type Mesh struct {
	st     *State
	pool   *nostr.SimplePool
	bind   *udpBind
	stun   *stunClient
	dev    *device.Device
	tunDev tun.Device

	mu       sync.Mutex
	roster   *Roster
	me       *Member
	peers    map[string]*peer // nostr pubkey -> peer
	external []netip.AddrPort
	port     uint16
	rosterCh chan struct{}
	onRoster func(*Roster) // モード側（TUN の経路設定など）
	pingFn   func(context.Context, netip.Addr) (time.Duration, error)
}

const punchMagic = "NMSHPNCH"

func (m *Mesh) logf(format string, a ...any) { log.Printf(format, a...) }

func newMesh(st *State) *Mesh {
	m := &Mesh{st: st, peers: map[string]*peer{}, rosterCh: make(chan struct{}, 1)}
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
	m.pool = nostr.NewSimplePool(context.Background(), nostr.WithAuthHandler(func(ctx context.Context, ev nostr.RelayEvent) error {
		return ev.Event.Sign(st.Keys.NostrSK)
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
		m.applyRoster(r)
	}
}

func (m *Mesh) handleRosterEvent(ev *nostr.Event) {
	m.mu.Lock()
	cur := m.roster
	m.mu.Unlock()
	r, err := acceptRoster(ev, m.st.Cfg.Network, m.st.Cfg.Admins, cur, time.Now())
	if err != nil {
		if cur == nil || !strings.HasPrefix(err.Error(), "古い版") {
			m.logf("名簿を拒否: %v", err)
		}
		return
	}
	saveJSON(m.rosterPath(), ev, 0600)
	m.applyRoster(r)
}

func (m *Mesh) applyRoster(r *Roster) {
	m.mu.Lock()
	m.roster = r
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
			ck, err := nip44.GenerateConversationKey(mem.Pubkey, m.st.Keys.NostrSK)
			if err != nil {
				continue
			}
			p.convKey = ck
			h := sha256.Sum256(append([]byte("nmesh-punch"), ck[:]...))
			p.punchKey = h[:]
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
	cb := m.onRoster
	m.mu.Unlock()
	if me == nil {
		m.logf("名簿 v%d を受信。ただしこの端末（%s）は名簿にありません", r.Version, m.st.Pub[:12])
	} else {
		m.logf("名簿 v%d を適用: 自分=%s %s、メンバー %d", r.Version, me.Name, me.IP, len(r.Members))
	}
	if cb != nil {
		cb(r)
	}
	select {
	case m.rosterCh <- struct{}{}:
	default:
	}
}

// ---- WireGuard 設定 ----

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

// ---- 告知 ----

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

func (m *Mesh) sendAnnounce(ctx context.Context, p *peer, reply bool) {
	m.mu.Lock()
	if m.roster == nil || m.me == nil || p == nil {
		m.mu.Unlock()
		return
	}
	ck := p.convKey
	to := p.pub
	name := p.name
	m.mu.Unlock()
	a := announce{Network: m.st.Cfg.Network, WgPub: m.st.WgPub, Cands: m.candidates(), TS: time.Now().Unix(), Reply: reply}
	b, _ := json.Marshal(a)
	ct, err := nip44.Encrypt(string(b), ck)
	if err != nil {
		return
	}
	ev := nostr.Event{Kind: KindAnnounce, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"p", to}}, Content: ct}
	if err := ev.Sign(m.st.Keys.NostrSK); err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ok := 0
	var errs []string
	for r := range m.pool.PublishMany(cctx, m.st.Cfg.Relays, ev) {
		if r.Error == nil {
			ok++
		} else {
			errs = append(errs, r.RelayURL+": "+r.Error.Error())
		}
	}
	if ok == 0 {
		m.logf("告知の送信に失敗 → %s: %s", name, strings.Join(errs, "; "))
	}
}

func (m *Mesh) handleAnnounce(ctx context.Context, ev *nostr.Event) {
	m.mu.Lock()
	p := m.peers[ev.PubKey]
	m.mu.Unlock()
	if p == nil {
		return // 名簿にない送り主は無視
	}
	if ok, err := ev.CheckSignature(); !ok || err != nil {
		return
	}
	pt, err := nip44.Decrypt(ev.Content, p.convKey)
	if err != nil {
		return
	}
	var a announce
	if json.Unmarshal([]byte(pt), &a) != nil || a.Network != m.st.Cfg.Network {
		return
	}
	age := time.Since(time.Unix(a.TS, 0))
	if age > 2*time.Minute || age < -2*time.Minute {
		return
	}
	if k, err := hex.DecodeString(a.WgPub); err != nil || len(k) != 32 {
		return
	}
	var cands []netip.AddrPort
	for _, c := range a.Cands {
		if ap, err := netip.ParseAddrPort(c); err == nil && len(cands) < 16 {
			cands = append(cands, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		}
	}
	m.mu.Lock()
	changed := p.wgPub != a.WgPub
	if changed && p.wgPub != "" && m.dev != nil {
		m.dev.IpcSet("public_key=" + p.wgPub + "\nremove=true\n")
	}
	first := p.wgPub == ""
	p.wgPub = a.WgPub
	p.cands = rankCands(cands, m.localPrefixes())
	p.lastAnn = time.Now()
	p.punchUntil = time.Now().Add(20 * time.Second)
	if !p.endpoint.IsValid() && len(p.cands) > 0 {
		p.endpoint = p.cands[0]
	}
	if changed || first {
		m.ipcPeerLocked(p)
		m.logf("相手を登録: %s（候補 %d 件）", p.name, len(p.cands))
	}
	doReply := !a.Reply && time.Since(p.lastReply) > 5*time.Second
	if doReply {
		p.lastReply = time.Now()
	}
	m.mu.Unlock()
	if doReply {
		go m.sendAnnounce(ctx, p, true)
	}
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

// ---- ホールパンチ ----
// 形式: magic(8) | type(1: ping, 2: pong) | 送り主 nostr pubkey(32) | nonce(8) | hmac(16)

func (m *Mesh) punchPacket(typ byte, p *peer, nonce []byte) []byte {
	pk, _ := hex.DecodeString(m.st.Pub)
	b := make([]byte, 0, 8+1+32+8+16)
	b = append(b, punchMagic...)
	b = append(b, typ)
	b = append(b, pk...)
	b = append(b, nonce...)
	mac := hmac.New(sha256.New, p.punchKey)
	mac.Write(b)
	return append(b, mac.Sum(nil)[:16]...)
}

func (m *Mesh) handlePunch(b []byte, from netip.AddrPort) {
	if len(b) != 8+1+32+8+16 {
		return
	}
	pub := hex.EncodeToString(b[9:41])
	m.mu.Lock()
	p := m.peers[pub]
	if p == nil || p.punchKey == nil {
		m.mu.Unlock()
		return
	}
	mac := hmac.New(sha256.New, p.punchKey)
	mac.Write(b[:49])
	if !hmac.Equal(mac.Sum(nil)[:16], b[49:]) {
		m.mu.Unlock()
		return
	}
	typ := b[8]
	p.punchRx++
	_, known := p.confirmed[from]
	p.confirmed[from] = time.Now()
	nonce := append([]byte(nil), b[41:49]...)
	update := false
	if !known {
		best := m.bestConfirmedLocked(p)
		if best.IsValid() && best != p.endpoint {
			p.endpoint = best
			update = true
		}
	}
	if update {
		m.ipcPeerLocked(p)
		m.logf("直接つながる住所を確認: %s → %s", p.name, p.endpoint)
	}
	var reply []byte
	if typ == 1 {
		reply = m.punchPacket(2, p, nonce)
	}
	m.mu.Unlock()
	if reply != nil {
		m.bind.SendRaw(reply, from)
	}
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
			if time.Now().After(p.punchUntil) || len(p.cands) == 0 {
				continue
			}
			nonce := make([]byte, 8)
			rand.Read(nonce)
			jobs = append(jobs, job{m.punchPacket(1, p, nonce), append([]netip.AddrPort(nil), p.cands...)})
		}
		m.mu.Unlock()
		for _, j := range jobs {
			for _, to := range j.to {
				m.bind.SendRaw(j.pkt, to)
			}
		}
	}
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

func (m *Mesh) Run(ctx context.Context, mk func(m *Mesh, me *Member) (tun.Device, error)) error {
	cfg := m.st.Cfg
	if cfg.Network == "" || len(cfg.Admins) == 0 {
		return fmt.Errorf("ネットワーク未設定（nmesh join か nmesh admin create を先に）")
	}
	m.loadCachedRoster()

	// 名簿の購読（管理者の署名のみ）
	go func() {
		f := nostr.Filter{Kinds: []int{KindRoster}, Authors: cfg.Admins, Tags: nostr.TagMap{"d": {cfg.Network}}}
		for ev := range m.pool.SubscribeMany(ctx, cfg.Relays, f) {
			m.handleRosterEvent(ev.Event)
		}
	}()

	// 名簿に自分が載るまで待つ
	m.logf("名簿を待っています（network=%s、自分=%s）", cfg.Network, m.st.Pub)
	for {
		m.mu.Lock()
		me := m.me
		m.mu.Unlock()
		if me != nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.rosterCh:
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

	// 告知の購読
	go func() {
		f := nostr.Filter{Kinds: []int{KindAnnounce}, Tags: nostr.TagMap{"p": {m.st.Pub}}, Since: ptrTS(nostr.Now() - 60)}
		for ev := range m.pool.SubscribeMany(ctx, cfg.Relays, f) {
			m.handleAnnounce(ctx, ev.Event)
		}
	}()
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
	lastCands := ""
	announceAll := func() {
		m.mu.Lock()
		var ps []*peer
		for _, p := range m.peers {
			ps = append(ps, p)
		}
		m.mu.Unlock()
		for _, p := range ps {
			go m.sendAnnounce(ctx, p, false)
		}
		lastCands = strings.Join(m.candidates(), ",")
	}
	announceAll()

	annT := time.NewTicker(30 * time.Second)
	stunT := time.NewTicker(60 * time.Second)
	netT := time.NewTicker(5 * time.Second)
	defer annT.Stop()
	defer stunT.Stop()
	defer netT.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-m.rosterCh:
			announceAll()
		case <-annT.C:
			announceAll()
		case <-stunT.C:
			refreshExternal()
		case <-netT.C:
			m.writeStatus()
			if c := strings.Join(m.candidates(), ","); c != lastCands {
				m.logf("ネットワークの変化を検知、告知し直します")
				refreshExternal()
				announceAll()
			}
		}
	}
}

func ptrTS(t nostr.Timestamp) *nostr.Timestamp { return &t }

var _ = binary.BigEndian
