# nmesh

Nostr で見つけ合い、WireGuard で直接つながるメッシュ VPN（試作）。

- 中央サーバーなし。Nostr リレーで名簿（管理者署名）と接続情報（NIP-44 暗号化）を受け渡す。
- データは WireGuard（wireguard-go）で端末どうし直接。STUN とホールパンチで NAT を越える。中継はしない。
- 既定は root 不要のユーザー空間モード（SOCKS5 と ポート公開）。`--mode tun` で OS のインターフェースを作る。

```sh
# 管理者の端末
nmesh init
nmesh admin create mymac
# 参加する端末
nmesh init
nmesh join <ネットワークID> <管理者npub>
# 管理者が追加
nmesh admin add <npub> linux1
# 両方で
nmesh up
nmesh status
nmesh ping linux1
curl --socks5-hostname 127.0.0.1:1080 http://linux1.mesh/
```

詳しくは [DESIGN.md](DESIGN.md)。状態：開発中（M1）。
