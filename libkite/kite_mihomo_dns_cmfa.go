//go:build android && cmfa

package libv2ray

import (
	"net/netip"

	mihomoDNS "github.com/metacubex/mihomo/dns"
)

func updateMihomoSystemDNS(servers string) {
	var list []string
	for _, server := range splitList(servers) {
		if addr, err := netip.ParseAddr(server); err == nil {
			list = append(list, netip.AddrPortFrom(addr, 53).String())
		}
	}
	mihomoDNS.UpdateSystemDNS(list)
	mihomoDNS.FlushCacheWithDefaultResolver()
}
