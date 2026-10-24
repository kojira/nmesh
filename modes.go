package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ---- ユーザー空間モード：root も TUN も不要 ----

func userspaceMode(ctx context.Context) func(m *Mesh, me *Member) (tun.Device, error) {
	return func(m *Mesh, me *Member) (tun.Device, error) {
		ip, err := netip.ParseAddr(me.IP)
		if err != nil {
			return nil, err
		}
		td, tnet, err := netstack.CreateNetTUN([]netip.Addr{ip}, nil, m.st.Cfg.MTU)
		if err != nil {
			return nil, err
		}
		// メッシュから受ける：指定ポートを手元へ転送
		for _, e := range m.st.Cfg.Expose {
			l, err := tnet.ListenTCP(&net.TCPAddr{IP: ip.AsSlice(), Port: e.Port})
			if err != nil {
				return nil, fmt.Errorf("expose %d: %w", e.Port, err)
			}
			m.logf("公開: メッシュ %s:%d → %s", ip, e.Port, e.To)
			go func(l net.Listener, to string) {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						d, err := net.DialTimeout("tcp", to, 5*time.Second)
						if err != nil {
							return
						}
						defer d.Close()
						pipe(c, d)
					}()
				}
			}(l, e.To)
		}
		// ping に応答させるため ICMP エコーは netstack が処理する
		// メッシュへ出る：SOCKS5
		if m.st.Cfg.Socks != "" {
			l, err := net.Listen("tcp", m.st.Cfg.Socks)
			if err != nil {
				return nil, fmt.Errorf("socks %s: %w", m.st.Cfg.Socks, err)
			}
			m.logf("SOCKS5: %s（メッシュ内の IP か名前へ接続）", m.st.Cfg.Socks)
			go func() {
				<-ctx.Done()
				l.Close()
			}()
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					go m.socks(c, func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
						return tnet.DialContextTCPAddrPort(ctx, addr)
					})
				}
			}()
		}
		m.pingFn = func(ctx context.Context, dst netip.Addr) (time.Duration, error) {
			return netstackPing(ctx, tnet, ip, dst)
		}
		return td, nil
	}
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); closeWrite(a); done <- struct{}{} }()
	go func() { io.Copy(b, a); closeWrite(b); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// resolve はメッシュ内の名前を IP にする（名前.ドメイン か 名前）。
func (m *Mesh) resolve(host string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a, true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.roster == nil {
		return netip.Addr{}, false
	}
	if mem := m.roster.byName(host); mem != nil {
		a, err := netip.ParseAddr(mem.IP)
		return a, err == nil
	}
	return netip.Addr{}, false
}

func (m *Mesh) inMesh(a netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.roster == nil {
		return false
	}
	p, err := netip.ParsePrefix(m.roster.CIDR)
	return err == nil && p.Contains(a)
}

// socks は最小限の SOCKS5（認証なし・CONNECT のみ）。行き先はメッシュ内だけ。
func (m *Mesh) socks(c net.Conn, dial func(context.Context, netip.AddrPort) (net.Conn, error)) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch buf[3] {
	case 1:
		io.ReadFull(c, buf[:4])
		host = netip.AddrFrom4([4]byte(buf[:4])).String()
	case 3:
		io.ReadFull(c, buf[:1])
		n := int(buf[0])
		io.ReadFull(c, buf[:n])
		host = string(buf[:n])
	case 4:
		io.ReadFull(c, buf[:16])
		host = netip.AddrFrom16([16]byte(buf[:16])).String()
	default:
		return
	}
	io.ReadFull(c, buf[:2])
	port := binary.BigEndian.Uint16(buf[:2])
	ip, ok := m.resolve(host)
	if !ok || !m.inMesh(ip) {
		c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}) // ルールで拒否
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	d, err := dial(ctx, netip.AddrPortFrom(ip, port))
	cancel()
	if err != nil {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer d.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c.SetDeadline(time.Time{})
	pipe(c, d)
}

// ---- TUN モード：OS にインターフェースを作る（root が必要） ----

func tunMode(m *Mesh, me *Member) (tun.Device, error) {
	name := m.st.Cfg.TunName
	if runtime.GOOS == "darwin" {
		name = "utun"
	}
	td, err := tun.CreateTUN(name, m.st.Cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("TUN 作成失敗（root が必要）: %w", err)
	}
	real, _ := td.Name()
	m.mu.Lock()
	cidr := m.roster.CIDR
	m.mu.Unlock()
	pfx := netip.MustParsePrefix(cidr)
	var cmds [][]string
	switch runtime.GOOS {
	case "linux":
		cmds = [][]string{
			{"ip", "addr", "add", me.IP + "/" + strconv.Itoa(pfx.Bits()), "dev", real},
			{"ip", "link", "set", real, "up"},
		}
	case "darwin":
		cmds = [][]string{
			{"ifconfig", real, "inet", me.IP, me.IP, "netmask", "255.255.255.255", "up"},
			{"route", "-q", "-n", "add", "-net", cidr, "-interface", real},
		}
	default:
		return nil, fmt.Errorf("%s は未対応", runtime.GOOS)
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			td.Close()
			return nil, fmt.Errorf("%s: %v %s", strings.Join(c, " "), err, out)
		}
	}
	m.logf("TUN %s: %s（経路 %s）", real, me.IP, cidr)
	m.pingFn = nil
	return td, nil
}
