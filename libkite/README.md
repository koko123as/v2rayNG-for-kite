# libkite

`libkite` builds `V2rayNG/app/libs/libv2ray.aar`, the only native Go library of the app.
gomobile allows one Go runtime per app, so Xray, mihomo and sing-box are compiled into the
same AAR and only one of them runs at a time.

| Core | Version | Source |
| --- | --- | --- |
| Xray | `XRAY_VERSION` (module `XRAY_MODULE_VERSION`) | `libv2ray_*.go` copied from the `AndroidLibXrayLite` submodule (`ANDROIDLIBXRAYLITE_VERSION`) |
| mihomo | `MIHOMO_VERSION` | `github.com/metacubex/mihomo`, built with the `cmfa` tag (as ClashMetaForAndroid) |
| sing-box | `SING_BOX_VERSION` | `github.com/sagernet/sing-box`, driven through `box.New` with its own platform interface |

All pins live in [`version.properties`](../version.properties) and are checked by
[`tools/verify_libkite.py`](../tools/verify_libkite.py) (which also asserts that
`github.com/sagernet/sing` stays at the version sing-box requires and writes
`libkite/build/core-module-bumps.txt`). Only `android/arm64` is built.

## Java API

The Go package is still `libv2ray`, so the AndroidLibXrayLite API (`Libv2ray.newCoreController`,
`CoreController.startLoop`, `Libv2ray.measureOutboundDelay`, …) is unchanged. `kite_*.go` add:

| Call | Purpose |
| --- | --- |
| `registerKitePlatform(KitePlatform)` | socket protect (`VpnService.protect`), `getConnectionOwnerUid`, package names, `openTun` for sing-box, interfaces, logs |
| `startKiteCore(core, content, CoreOptions)` / `stopKiteCore()` / `runningKiteCore()` | run mihomo or sing-box; the profile keeps its proxies/groups/rules/DNS, inbounds are replaced for the run mode |
| `measureKiteDelay`, `measureKiteOutboundDelay`, `measureKiteProxyDelay` | delay test through the running core, offline profile test, one proxy |
| `queryKiteTrafficStats()` | same `tag,direction,value;` format as `CoreController.queryAllOutboundTrafficStats` (`proxy` / `direct`) |
| `getKiteGroups()` / `selectKiteOutbound(group, name)` | policy groups (mihomo proxy-groups, sing-box selector/urltest) |
| `detectCoreConfig`, `checkCoreConfig` | import: Clash YAML → `mihomo`, typed-outbound JSON → `sing-box`, protocol JSON → `xray` |
| `updateSystemDNS`, `updateDefaultInterface` | underlying network DNS (mihomo `system`) and default interface (sing-box) |
| `mihomoVersion()`, `singBoxVersion()` | About page |

## Run modes

No core is wrapped: traffic goes straight into the core that runs the profile.

- VPN: mihomo gets a dup of the VpnService descriptor in `tun.file-descriptor` (gVisor stack,
  `auto-route`, `auto-redirect`, `auto-detect-interface` off, external controller off). sing-box
  gets a `tun` inbound; when it starts, `KitePlatform.openTun` builds the VpnService from the
  addresses/routes sing-box computed plus the app's per-app settings, and sing-box runs on a dup.
- Root: mihomo `tproxy-port`/`redir-port`/`dns.listen`, sing-box `tproxy`/`redirect`/`direct`
  (DNS) inbounds; `RootProxyManager` points iptables TPROXY/REDIRECT rules at those ports.
- Proxy only: the core's own mixed inbound.

Outbound sockets: Xray `internet.RegisterDialerController`, mihomo `dialer.DefaultSocketHook`,
sing-box platform `AutoDetectInterfaceControl`, all to `KitePlatform.protect`. Process lookup
(per-app routing rules) goes to `getConnectionOwnerUid` for all three cores.

## Geo data

Xray's `geoip.dat` / `geosite.dat` (shipped in the AAR `assets/`, copied by the app to its asset
directory) are shared: mihomo reads copies in its home directory (geodata mode); sing-box 1.14 has
no geosite database, so rule-sets referenced as `kitegeo:<site|ip>:<file>:<code>[@attr]` are
generated as local `.srs` files (mihomo: classical rule providers for `ext:` files).

## Building and upgrading

```sh
libkite/build.sh test     # copy libv2ray sources from the submodule, run Go tests
libkite/build.sh          # verify pins, gomobile bind -target=android/arm64
python3 tools/bump_core.py <xray|mihomo|sing-box> <version> [--dry-run]
```

Upgrade one core per branch, run the `Build APK` workflow (`workflow_dispatch` on the branch),
then check on a device: start, stop and switch each core in every run mode, ports released after
switching, routing hits, and no new warnings in the log.
