//go:build !(android && cmfa)

package libv2ray

// Only mihomo built for Android with the cmfa tag needs the system DNS pushed
// in; elsewhere it reads the system resolver itself.
func updateMihomoSystemDNS(servers string) {}
