package libv2ray

// Multi-core extension of the AndroidLibXrayLite API.
//
// The app loads one gomobile AAR, so Xray (the unchanged libv2ray API in
// libv2ray_*.go, copied from the AndroidLibXrayLite submodule at build time),
// mihomo and sing-box live in the same Go runtime. Only one of them runs at a
// time; the Kotlin service layer stops the previous core before starting
// another one.
//
// mihomo and sing-box are driven directly: there is no local SOCKS hop and no
// hev-socks5-tunnel in front of them.
//   - VPN mode: mihomo receives the VpnService descriptor through its tun
//     "file-descriptor"; sing-box opens its own tun inbound through
//     KitePlatform.OpenTun, which builds the VpnService on the Kotlin side.
//   - Root mode: each core opens its own tproxy/redirect inbounds, the app
//     installs iptables rules pointing at those ports.
//   - Proxy-only mode: each core opens its own mixed inbound.

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	mihomoDialer "github.com/metacubex/mihomo/component/dialer"
	xrayInternet "github.com/xtls/xray-core/transport/internet"
)

// Core names shared with the Kotlin side.
const (
	CoreXray    = "xray"
	CoreMihomo  = "mihomo"
	CoreSingBox = "sing-box"
)

// Run modes shared with the Kotlin side.
const (
	ModeVPN   = "vpn"
	ModeProxy = "proxy"
	ModeRoot  = "root"
)

// Log levels passed to KitePlatform.WriteLog.
const (
	LogLevelDebug   = 0
	LogLevelInfo    = 1
	LogLevelWarning = 2
	LogLevelError   = 3
)

// KitePlatform is implemented by the Android service process.
type KitePlatform interface {
	// Protect excludes a socket from the VPN (VpnService.protect). Outside VPN
	// mode it returns true without doing anything.
	Protect(fd int32) bool
	// FindConnectionOwner returns the uid owning a connection
	// (ConnectivityManager.getConnectionOwnerUid) or -1. ipProtocol is 6 (TCP)
	// or 17 (UDP).
	FindConnectionOwner(ipProtocol int32, srcIP string, srcPort int32, dstIP string, dstPort int32) int32
	// PackageNameByUid returns the first package name of a uid or "".
	PackageNameByUid(uid int32) string
	// OpenTun establishes the VpnService interface sing-box asked for and
	// returns its descriptor. The app keeps ownership of that descriptor.
	OpenTun(options *TunConfig) (int32, error)
	// NetworkInterfaces lists the device interfaces, one per line:
	// name|index|mtu|flags|addr/prefix,...|dns,...|type|metered
	// type is wifi, cellular, ethernet or other. flags uses net.Flags bits.
	NetworkInterfaces() string
	// WriteLog forwards one core log line.
	WriteLog(level int32, message string)
}

// TunConfig is what sing-box asks the VpnService to be. All lists are comma
// separated.
type TunConfig struct {
	Inet4Address string
	Inet6Address string
	MTU          int32
	AutoRoute    bool
	// Routes to add, already reduced by the exclusions sing-box computed.
	Inet4RouteRange string
	Inet6RouteRange string
	DNSServer       string
	IncludePackage  string
	ExcludePackage  string
	HTTPProxyServer string
	HTTPProxyPort   int32
}

// CoreOptions describes how the app wants the core to run. The core's own
// configuration keeps its proxies, groups, rules and DNS; its inbounds (and
// mihomo's tun / listener ports) are replaced to fit the run mode.
type CoreOptions struct {
	Mode string
	// VPN mode, mihomo: the VpnService descriptor. A private dup is handed to
	// mihomo, the original stays owned by the app.
	TunFd    int32
	TunInet4 string // CIDR of the VpnService IPv4 address
	TunInet6 string // CIDR of the VpnService IPv6 address, empty without IPv6
	TunMTU   int32
	// VPN mode, sing-box tun inbound routing.
	TunBypassLan bool
	TunDNS       string // DNS server address the VpnService announces
	IPv6         bool
	// Local mixed (HTTP+SOCKS) inbound, 0 disables it.
	MixedPort   int32
	MixedListen string
	MixedUser   string
	MixedPass   string
	// Root mode inbounds, 0 disables them. Also used in VPN mode for root LAN
	// sharing.
	TProxyPort int32
	RedirPort  int32
	TProxyListen string
	// DNS listener for root mode DNS redirection, 0 disables it.
	DNSPort   int32
	DNSListen string
	// Working directory of the core (cache file, providers, rule-sets).
	HomeDir string
	// Directory holding geoip.dat / geosite.dat shared with Xray.
	AssetDir string
	// debug, info, warning, error or none. Empty keeps the config's level.
	LogLevel string
	// Comma separated DNS servers of the underlying network (mihomo "system").
	SystemDNS string
	// Sniff TLS/HTTP/QUIC host names on the tun/tproxy inbounds.
	Sniffing bool
}

var (
	kitePlatform atomic.Pointer[platformHolder]
	coreAccess   sync.Mutex
	runningKite  atomic.Value // string: CoreMihomo, CoreSingBox or ""
)

type platformHolder struct {
	platform KitePlatform
}

func init() {
	runningKite.Store("")
	// Both hooks are process wide and cannot be removed, so they are installed
	// once and read the current platform on every call.
	_ = xrayInternet.RegisterDialerController(func(network, address string, conn syscall.RawConn) error {
		return protectRawConn(conn)
	})
	mihomoDialer.DefaultSocketHook = func(network, address string, conn syscall.RawConn) error {
		return protectRawConn(conn)
	}
}

// RegisterKitePlatform installs the Android callbacks used by every core for
// socket protection, process lookup and logging. Pass nil to remove them.
func RegisterKitePlatform(platform KitePlatform) {
	if platform == nil {
		kitePlatform.Store(nil)
		return
	}
	kitePlatform.Store(&platformHolder{platform: platform})
}

func currentPlatform() KitePlatform {
	holder := kitePlatform.Load()
	if holder == nil {
		return nil
	}
	return holder.platform
}

func protectFd(fd int) error {
	platform := currentPlatform()
	if platform == nil {
		return nil
	}
	if !platform.Protect(int32(fd)) {
		return fmt.Errorf("protect socket %d failed", fd)
	}
	return nil
}

func protectRawConn(conn syscall.RawConn) error {
	if currentPlatform() == nil {
		return nil
	}
	var protectErr error
	err := conn.Control(func(fd uintptr) {
		protectErr = protectFd(int(fd))
	})
	if err != nil {
		return err
	}
	return protectErr
}

func kiteLog(level int32, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if platform := currentPlatform(); platform != nil {
		platform.WriteLog(level, message)
		return
	}
	fmt.Fprintln(os.Stderr, message)
}

// findOwnerUid asks Android which uid owns a connection. Returns -1 when it is
// not known.
func findOwnerUid(network string, src netip.AddrPort, dst netip.AddrPort) int32 {
	platform := currentPlatform()
	if platform == nil || !src.IsValid() || !dst.IsValid() || dst.Port() == 0 {
		return -1
	}
	var protocol int32
	switch strings.ToLower(network) {
	case "tcp", "tcp4", "tcp6":
		protocol = syscall.IPPROTO_TCP
	case "udp", "udp4", "udp6":
		protocol = syscall.IPPROTO_UDP
	default:
		return -1
	}
	return platform.FindConnectionOwner(protocol, src.Addr().Unmap().String(), int32(src.Port()), dst.Addr().Unmap().String(), int32(dst.Port()))
}

func packageNameByUid(uid int32) string {
	platform := currentPlatform()
	if platform == nil || uid < 0 {
		return ""
	}
	return platform.PackageNameByUid(uid)
}

// RunningKiteCore reports mihomo or sing-box when one of them runs, else "".
// Xray keeps reporting through CoreController.IsRunning.
func RunningKiteCore() string {
	return runningKite.Load().(string)
}

// IsKiteCoreRunning reports whether mihomo or sing-box runs.
func IsKiteCoreRunning() bool {
	return RunningKiteCore() != ""
}

// StartKiteCore starts mihomo or sing-box with the given configuration,
// stopping whichever of the two ran before.
func StartKiteCore(core string, content string, options *CoreOptions) error {
	if options == nil {
		return errors.New("missing core options")
	}
	coreAccess.Lock()
	defer coreAccess.Unlock()
	stopKiteCoreLocked()
	var err error
	switch core {
	case CoreMihomo:
		err = startMihomo(content, options)
	case CoreSingBox:
		err = startSingBox(content, options)
	default:
		return fmt.Errorf("unknown core: %s", core)
	}
	if err != nil {
		stopKiteCoreLocked()
		return err
	}
	runningKite.Store(core)
	kiteLog(LogLevelInfo, "%s started (%s mode)", core, options.Mode)
	return nil
}

// StopKiteCore stops mihomo or sing-box and releases its ports and
// descriptors. Calling it when nothing runs is a no-op.
func StopKiteCore() error {
	coreAccess.Lock()
	defer coreAccess.Unlock()
	stopKiteCoreLocked()
	return nil
}

func stopKiteCoreLocked() {
	core := RunningKiteCore()
	stopMihomo()
	stopSingBox()
	runningKite.Store("")
	if core != "" {
		kiteLog(LogLevelInfo, "%s stopped", core)
	}
}

func splitList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func parsePrefixes(value string) []netip.Prefix {
	var result []netip.Prefix
	for _, item := range splitList(value) {
		if prefix, err := netip.ParsePrefix(item); err == nil {
			result = append(result, prefix)
		} else if addr, err := netip.ParseAddr(item); err == nil {
			result = append(result, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return result
}

func dupFd(fd int) (int, error) {
	newFd, err := syscall.Dup(fd)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(newFd)
	return newFd, nil
}

func listenOrDefault(listen string, def string) string {
	if strings.TrimSpace(listen) == "" {
		return def
	}
	return strings.TrimSpace(listen)
}
