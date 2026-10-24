# nmesh

Nostr で見つけ合い、WireGuard で直接つながるメッシュ VPN（試作）。

- 中央サーバーなし。名簿（管理者署名）と接続情報は、エフェメラルの Nostr イベントで、二重に暗号化して受け渡す。
  - 外側の鍵は1分ごとに一方向に進め、内側は使い捨ての鍵どうしで暗号化する。鍵が漏れても、過去のやりとりは読めない。
  - 普段は購読しているだけで、何も送らない。起動したとき、ネットワークが変わったとき、つながらなくなったときだけ問い合わせる。
- データは WireGuard（wireguard-go）で端末どうし直接。STUN とホールパンチで NAT を越える。中継はしない。
- 既定は root 不要のユーザー空間モード（SOCKS5 と ポート公開）。`--mode tun` で OS のインターフェースを作る。

```sh
# 管理者の端末
nmesh init
nmesh admin create mymac
# 参加する端末
nmesh init
nmesh id                      # 表示された npub を管理者へ
# 管理者が追加すると招待文字列が出る（Nostr を通さず、安全な方法で渡す）
nmesh admin add <npub> linux1
# 参加する端末で
nmesh join nmesh-invite:...
# 両方で
nmesh up
nmesh status
nmesh ping linux1
curl --socks5-hostname 127.0.0.1:1080 http://linux1.mesh/
```

詳しくは [DESIGN.md](DESIGN.md)。状態：開発中（M1）。
