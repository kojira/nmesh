package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/miekg/dns"
)

// メッシュ内の名前（<端末名>.<ドメイン>）だけに答える小さな DNS。
// それ以外の名前には REFUSED を返す（他の DNS の邪魔をしない）。

func (m *Mesh) dnsHandler(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	m.mu.Lock()
	r := m.roster
	m.mu.Unlock()
	if r == nil || len(req.Question) != 1 {
		resp.Rcode = dns.RcodeServerFailure
		w.WriteMsg(resp)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	suffix := "." + strings.ToLower(r.Domain)
	if !strings.HasSuffix(name, suffix) && name != strings.ToLower(r.Domain) {
		resp.Rcode = dns.RcodeRefused
		w.WriteMsg(resp)
		return
	}
	mem := r.byName(strings.TrimSuffix(name, suffix))
	if mem == nil {
		resp.Rcode = dns.RcodeNameError
		w.WriteMsg(resp)
		return
	}
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
		ip, _ := netip.ParseAddr(mem.IP)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.IP(ip.AsSlice()),
		})
	}
	w.WriteMsg(resp)
}

// startDNS は addr（UDP と TCP）で待ち受ける。
func (m *Mesh) startDNS(addr string) error {
	h := dns.HandlerFunc(m.dnsHandler)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("DNS %s: %w", addr, err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return fmt.Errorf("DNS %s: %w", addr, err)
	}
	go (&dns.Server{PacketConn: pc, Handler: h}).ActivateAndServe()
	go (&dns.Server{Listener: l, Handler: h}).ActivateAndServe()
	m.logf("DNS: %s（%s の名前だけに答えます）", addr, m.roster.Domain)
	return nil
}

// installResolver は OS に「このドメインだけ nmesh の DNS に聞く」と設定する（root が必要）。
// 戻り値は後片付けの関数。
func installResolver(domain, host string, port int, iface string) (func(), error) {
	switch runtime.GOOS {
	case "darwin":
		p := filepath.Join("/etc/resolver", domain)
		if b, err := os.ReadFile(p); err == nil && !strings.Contains(string(b), "# nmesh") {
			return nil, fmt.Errorf("%s は nmesh 以外が作ったファイルなので触りません", p)
		}
		os.MkdirAll("/etc/resolver", 0755)
		body := fmt.Sprintf("# nmesh\nnameserver %s\nport %d\n", host, port)
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			return nil, err
		}
		return func() { os.Remove(p) }, nil
	case "linux":
		if _, err := exec.LookPath("resolvectl"); err != nil {
			return nil, fmt.Errorf("resolvectl がないため DNS を OS に登録できません")
		}
		srv := host
		if port != 53 {
			srv = fmt.Sprintf("%s:%d", host, port)
		}
		for _, c := range [][]string{{"resolvectl", "dns", iface, srv}, {"resolvectl", "domain", iface, "~" + domain}} {
			if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
				return nil, fmt.Errorf("%s: %v %s", strings.Join(c, " "), err, out)
			}
		}
		return func() { exec.Command("resolvectl", "revert", iface).Run() }, nil
	}
	return nil, fmt.Errorf("%s は未対応", runtime.GOOS)
}
