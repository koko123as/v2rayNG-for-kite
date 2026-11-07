package libv2ray

// mihomo, embedded the way ClashMetaForAndroid embeds it (cmfa build tag):
// listeners and tun are taken from CoreOptions, not from the profile, and the
// external controller is off; the app talks to mihomo in process.

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	mihomoProcess "github.com/metacubex/mihomo/component/process"
	mihomoConfig "github.com/metacubex/mihomo/config"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	mihomoDNS "github.com/metacubex/mihomo/dns"
	mihomoExecutor "github.com/metacubex/mihomo/hub/executor"
	mihomoListener "github.com/metacubex/mihomo/listener"
	mihomoListenerConfig "github.com/metacubex/mihomo/listener/config"
	mihomoLog "github.com/metacubex/mihomo/log"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
)

var (
	mihomoLogDone chan struct{}
	mihomoTunFd   = -1
	// True once mihomo's tun took the dup; mihomo then closes it itself.
	mihomoTunOwned bool
	mihomoActive   bool
)

func init() {
	// With the cmfa tag mihomo resolves PROCESS-NAME rules through this hook
	// with the full connection metadata; Android answers with the package
	// name of the owning uid.
	mihomoProcess.DefaultPackageNameResolver = func(metadata *mihomoConstant.Metadata) (string, error) {
		src := netip.AddrPortFrom(metadata.SrcIP, metadata.SrcPort)
		dst := netip.AddrPortFrom(metadata.DstIP, metadata.DstPort)
		uid := findOwnerUid(metadata.NetWork.String(), src, dst)
		if uid < 0 {
			return "", mihomoProcess.ErrNotFound
		}
		metadata.Uid = uint32(uid)
		name := packageNameByUid(uid)
		if name == "" {
			return "", mihomoProcess.ErrNotFound
		}
		return name, nil
	}
}

func mihomoLogLevel(level string) (mihomoLog.LogLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return mihomoLog.DEBUG, true
	case "info":
		return mihomoLog.INFO, true
	case "warning", "warn":
		return mihomoLog.WARNING, true
	case "error":
		return mihomoLog.ERROR, true
	case "none", "silent":
		return mihomoLog.SILENT, true
	}
	return mihomoLog.WARNING, false
}

// prepareMihomoRaw applies the run mode to a parsed mihomo profile.
func prepareMihomoRaw(raw *mihomoConfig.RawConfig, options *CoreOptions) {
	if level, ok := mihomoLogLevel(options.LogLevel); ok {
		raw.LogLevel = level
	}
	// Ports come from the app only.
	raw.Port = 0
	raw.SocksPort = 0
	raw.MixedPort = 0
	raw.RedirPort = 0
	raw.TProxyPort = 0
	raw.ShadowSocksConfig = ""
	raw.VmessConfig = ""
	raw.TuicServer.Enable = false
	raw.Listeners = nil
	raw.Authentication = nil
	raw.AllowLan = false
	raw.BindAddress = "*"
	// The app owns routing; netlink based features are unavailable to apps.
	raw.Interface = ""
	raw.RoutingMark = 0
	raw.IPTables.Enable = false
	raw.ExternalController = ""
	raw.ExternalControllerTLS = ""
	raw.ExternalControllerUnix = ""
	raw.ExternalControllerPipe = ""
	raw.ExternalUI = ""
	raw.ExternalDohServer = ""
	raw.Tun.Enable = false
	raw.Tun.FileDescriptor = 0
	raw.DNS.Listen = ""

	if options.MixedPort > 0 {
		raw.MixedPort = int(options.MixedPort)
		listen := listenOrDefault(options.MixedListen, "127.0.0.1")
		if listen != "127.0.0.1" && listen != "::1" && listen != "localhost" {
			raw.AllowLan = true
			raw.BindAddress = listen
		}
		if options.MixedUser != "" {
			raw.Authentication = []string{options.MixedUser + ":" + options.MixedPass}
		}
	}
	if options.TProxyPort > 0 {
		raw.TProxyPort = int(options.TProxyPort)
		raw.AllowLan = true
	}
	if options.RedirPort > 0 {
		raw.RedirPort = int(options.RedirPort)
		raw.AllowLan = true
	}
	if options.DNSPort > 0 {
		raw.DNS.Enable = true
		raw.DNS.Listen = net2(listenOrDefault(options.DNSListen, "127.0.0.1"), int(options.DNSPort))
	}
	if options.Mode == ModeVPN {
		raw.Tun.Enable = true
		raw.Tun.Device = ""
		raw.Tun.Stack = mihomoConstant.TunGvisor
		raw.Tun.AutoRoute = false
		raw.Tun.AutoRedirect = false
		raw.Tun.AutoDetectInterface = false
		raw.Tun.StrictRoute = false
		raw.Tun.IncludePackage = nil
		raw.Tun.ExcludePackage = nil
		raw.Tun.IncludeUID = nil
		raw.Tun.ExcludeUID = nil
		raw.Tun.IncludeAndroidUser = nil
		if options.TunMTU > 0 {
			raw.Tun.MTU = uint32(options.TunMTU)
		}
		raw.Tun.Inet6Address = parsePrefixes(options.TunInet6)
		if len(raw.Tun.DNSHijack) == 0 {
			raw.Tun.DNSHijack = []string{"any:53", "tcp://any:53"}
		}
		// Placeholder; the real descriptor is set after parsing.
		raw.Tun.FileDescriptor = 1
	}
	if options.HomeDir != "" {
		raw.Profile.StoreSelected = true
	}
}

func net2(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

func mihomoHome(options *CoreOptions) string {
	home := options.HomeDir
	if home == "" {
		home = filepath.Join(os.TempDir(), "mihomo")
	}
	return home
}

func parseMihomo(content string, options *CoreOptions) (*mihomoConfig.Config, error) {
	home := mihomoHome(options)
	if err := os.MkdirAll(home, 0o755); err != nil {
		return nil, err
	}
	mihomoConstant.SetHomeDir(home)
	syncGeoForMihomo(options.AssetDir, home)
	raw, err := mihomoConfig.UnmarshalRawConfig([]byte(strings.TrimPrefix(content, "\ufeff")))
	if err != nil {
		return nil, fmt.Errorf("mihomo config: %w", err)
	}
	prepareMihomoRaw(raw, options)
	if err := prepareMihomoGeoProviders(raw, options.AssetDir, home); err != nil {
		return nil, err
	}
	config, err := mihomoConfig.ParseRawConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("mihomo config: %w", err)
	}
	return config, nil
}

func startMihomo(content string, options *CoreOptions) error {
	if options.SystemDNS != "" {
		UpdateSystemDNS(options.SystemDNS)
	}
	config, err := parseMihomo(content, options)
	if err != nil {
		return err
	}
	if options.Mode == ModeVPN {
		if options.TunFd <= 0 {
			return errors.New("mihomo: missing VPN descriptor")
		}
		// mihomo closes the descriptor it is given, so it gets its own dup;
		// the VpnService descriptor stays owned by the app.
		fd, err := dupFd(int(options.TunFd))
		if err != nil {
			return fmt.Errorf("mihomo: dup tun: %w", err)
		}
		mihomoTunFd = fd
		config.General.Tun.FileDescriptor = fd
		// parseTun derives the tun address from the fake-ip range; the gVisor
		// stack must use the address the VpnService was given.
		if inet4 := parsePrefixes(options.TunInet4); len(inet4) > 0 {
			config.General.Tun.Inet4Address = inet4
		}
		config.General.Tun.Inet6Address = parsePrefixes(options.TunInet6)
	}
	startMihomoLog()
	mihomoActive = true
	mihomoExecutor.ApplyConfig(config, true)
	if options.Mode == ModeVPN {
		mihomoTunOwned = mihomoListener.GetTunConf().Enable
		if !mihomoTunOwned {
			return errors.New("mihomo: tun did not start")
		}
	}
	return nil
}

func startMihomoLog() {
	done := make(chan struct{})
	mihomoLogDone = done
	subscription := mihomoLog.Subscribe()
	go func() {
		defer mihomoLog.UnSubscribe(subscription)
		for {
			select {
			case <-done:
				return
			case event, ok := <-subscription:
				if !ok {
					return
				}
				level := int32(LogLevelInfo)
				switch event.LogLevel {
				case mihomoLog.ERROR:
					level = LogLevelError
				case mihomoLog.WARNING:
					level = LogLevelWarning
				case mihomoLog.DEBUG:
					level = LogLevelDebug
				}
				kiteLog(level, "[mihomo] %s", event.Payload)
			}
		}
	}()
}

func stopMihomo() {
	if !mihomoActive {
		return
	}
	mihomoActive = false
	mihomoExecutor.Shutdown()
	closeMihomoListeners()
	if mihomoLogDone != nil {
		close(mihomoLogDone)
		mihomoLogDone = nil
	}
	// mihomo's tun closes its dup itself; if it never took it, close it here.
	// Closing it twice could hit a number Android reused for another tracked
	// descriptor, which aborts the process.
	if mihomoTunFd >= 0 {
		if !mihomoTunOwned {
			_ = syscall.Close(mihomoTunFd)
		}
		mihomoTunFd = -1
	}
	mihomoTunOwned = false
}

// closeMihomoListeners releases every port the profile opened, so the next
// core (or the next mihomo start) can bind them again.
func closeMihomoListeners() {
	tunnel := mihomoTunnel.Tunnel
	mihomoListener.PatchInboundListeners(map[string]mihomoConstant.InboundListener{}, tunnel, true)
	mihomoListener.ReCreateTun(mihomoListenerConfig.Tun{Enable: false}, tunnel)
	mihomoListener.ReCreateHTTP(0, tunnel)
	mihomoListener.ReCreateSocks(0, tunnel)
	mihomoListener.ReCreateRedir(0, tunnel)
	mihomoListener.ReCreateTProxy(0, tunnel)
	mihomoListener.ReCreateMixed(0, tunnel)
	mihomoListener.ReCreateShadowSocks("", tunnel)
	mihomoListener.ReCreateVmess("", tunnel)
	mihomoListener.ReCreateTuic(mihomoListenerConfig.TuicServer{}, tunnel)
	mihomoDNS.ReCreateServer("", nil, nil)
}

// UpdateSystemDNS gives mihomo the DNS servers of the underlying network,
// comma separated. With the cmfa tag mihomo's "system" resolver reads them
// from here instead of the OS.
func UpdateSystemDNS(servers string) {
	updateMihomoSystemDNS(servers)
}

// CheckMihomoConfig parses a mihomo profile without starting it.
func CheckMihomoConfig(content string) error {
	raw, err := mihomoConfig.UnmarshalRawConfig([]byte(strings.TrimPrefix(content, "\ufeff")))
	if err != nil {
		return err
	}
	if len(raw.Proxy) == 0 && len(raw.ProxyProvider) == 0 {
		return errors.New("no proxies or proxy-providers")
	}
	return nil
}
