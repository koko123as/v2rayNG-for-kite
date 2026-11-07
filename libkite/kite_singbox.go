package libv2ray

// sing-box, run through box.New with a platform interface implemented on top
// of KitePlatform (the same role libbox's PlatformInterface plays in
// sing-box-for-android, reduced to what this app needs).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	sJson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

// Inbound tags the app creates for each run mode.
const (
	singBoxTunTag      = "tun-in"
	singBoxMixedTag    = "mixed-in"
	singBoxTProxyTag   = "tproxy-in"
	singBoxRedirectTag = "redirect-in"
	singBoxDNSTag      = "dns-in"
)

type singBoxRunning struct {
	ctx      context.Context
	cancel   context.CancelFunc
	instance *box.Box
	platform *singBoxPlatform
}

var (
	singBoxAccess  sync.Mutex
	singBoxCurrent *singBoxRunning
	// The monitor of the running instance, fed by UpdateDefaultInterface.
	singBoxMonitor *singBoxInterfaceMonitor
)

func singBoxContext(home string) context.Context {
	ctx := context.Background()
	if home != "" {
		tempDir := filepath.Join(home, "tmp")
		_ = os.MkdirAll(tempDir, 0o755)
		ctx = filemanager.WithDefault(ctx, home, tempDir, os.Getuid(), os.Getgid())
	}
	return include.Context(ctx)
}

func parseSingBoxOptions(ctx context.Context, content string) (option.Options, error) {
	options, err := sJson.UnmarshalExtendedContext[option.Options](ctx, []byte(content))
	if err != nil {
		return option.Options{}, E.Cause(err, "decode sing-box config")
	}
	return options, nil
}

// prepareSingBoxJSON applies the run mode to a sing-box profile: inbounds are
// replaced, logging, cache file and APIs are adjusted, and the DNS hijack /
// sniff rules for the app's inbounds are put first.
func prepareSingBoxJSON(content string, options *CoreOptions) (string, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(normalizeJSONC(content)), &root); err != nil {
		return "", E.Cause(err, "decode sing-box config")
	}
	var inbounds []any
	var inboundTags []string
	addInbound := func(inbound map[string]any) {
		inbounds = append(inbounds, inbound)
		inboundTags = append(inboundTags, inbound["tag"].(string))
	}
	if options.Mode == ModeVPN {
		address := []string{}
		for _, prefix := range parsePrefixes(options.TunInet4) {
			address = append(address, prefix.String())
		}
		if options.IPv6 {
			for _, prefix := range parsePrefixes(options.TunInet6) {
				address = append(address, prefix.String())
			}
		}
		if len(address) == 0 {
			address = append(address, "172.19.0.1/30")
		}
		tunInbound := map[string]any{
			"type":         "tun",
			"tag":          singBoxTunTag,
			"address":      address,
			"auto_route":   true,
			"strict_route": false,
			// gVisor, as for mihomo: the system/mixed stack answers TCP from a
			// kernel listener on the tun address, but the app is excluded from
			// its own VPN, so those replies do not reliably return through the tun.
			"stack":        "gvisor",
		}
		if options.TunMTU > 0 {
			tunInbound["mtu"] = options.TunMTU
		}
		var exclude []string
		if options.TunBypassLan {
			exclude = append(exclude, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4")
			if options.IPv6 {
				exclude = append(exclude, "fc00::/7", "fe80::/10", "ff00::/8")
			}
		}
		if len(exclude) > 0 {
			tunInbound["route_exclude_address"] = exclude
		}
		addInbound(tunInbound)
	}
	if options.MixedPort > 0 {
		mixed := map[string]any{
			"type":        "mixed",
			"tag":         singBoxMixedTag,
			"listen":      listenOrDefault(options.MixedListen, "127.0.0.1"),
			"listen_port": options.MixedPort,
		}
		if options.MixedUser != "" {
			mixed["users"] = []any{map[string]any{"username": options.MixedUser, "password": options.MixedPass}}
		}
		addInbound(mixed)
	}
	if options.TProxyPort > 0 {
		addInbound(map[string]any{
			"type":        "tproxy",
			"tag":         singBoxTProxyTag,
			"listen":      listenOrDefault(options.TProxyListen, "::"),
			"listen_port": options.TProxyPort,
		})
	}
	if options.RedirPort > 0 {
		addInbound(map[string]any{
			"type":        "redirect",
			"tag":         singBoxRedirectTag,
			"listen":      listenOrDefault(options.TProxyListen, "::"),
			"listen_port": options.RedirPort,
		})
	}
	if options.DNSPort > 0 {
		addInbound(map[string]any{
			"type":        "direct",
			"tag":         singBoxDNSTag,
			"listen":      listenOrDefault(options.DNSListen, "127.0.0.1"),
			"listen_port": options.DNSPort,
		})
	}
	if inbounds == nil {
		inbounds = []any{}
	}
	root["inbounds"] = inbounds

	route, _ := root["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
	}
	var prepend []any
	if len(inboundTags) > 0 {
		prepend = append(prepend, map[string]any{"inbound": inboundTags, "action": "sniff"})
		prepend = append(prepend, map[string]any{"protocol": "dns", "action": "hijack-dns"})
	}
	if options.DNSPort > 0 {
		prepend = append(prepend, map[string]any{"inbound": []string{singBoxDNSTag}, "action": "hijack-dns"})
	}
	rules, _ := route["rules"].([]any)
	route["rules"] = append(prepend, rules...)
	// Outbound sockets go through KitePlatform.Protect only while the default
	// interface is followed; that is needed under the VpnService only.
	if options.Mode == ModeVPN {
		route["auto_detect_interface"] = true
	} else {
		delete(route, "auto_detect_interface")
	}
	delete(route, "default_interface")
	delete(route, "default_mark")
	delete(route, "override_android_vpn")
	root["route"] = route

	logOptions, _ := root["log"].(map[string]any)
	if logOptions == nil {
		logOptions = map[string]any{}
	}
	delete(logOptions, "output")
	logOptions["timestamp"] = false
	if level := singBoxLogLevel(options.LogLevel); level != "" {
		if level == "none" {
			logOptions["disabled"] = true
		} else {
			logOptions["level"] = level
			delete(logOptions, "disabled")
		}
	}
	root["log"] = logOptions

	experimental, _ := root["experimental"].(map[string]any)
	if experimental == nil {
		experimental = map[string]any{}
	}
	delete(experimental, "clash_api")
	delete(experimental, "v2ray_api")
	if options.HomeDir != "" {
		cacheFile, _ := experimental["cache_file"].(map[string]any)
		if cacheFile == nil {
			cacheFile = map[string]any{}
		}
		cacheFile["enabled"] = true
		cacheFile["path"] = filepath.Join(options.HomeDir, "cache.db")
		experimental["cache_file"] = cacheFile
	} else {
		delete(experimental, "cache_file")
	}
	root["experimental"] = experimental
	delete(root, "services")

	encoded, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return prepareSingBoxGeoRuleSets(string(encoded), options.AssetDir, options.HomeDir)
}

func singBoxLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return "debug"
	case "info":
		return "info"
	case "warning", "warn":
		return "warn"
	case "error":
		return "error"
	case "none", "silent":
		return "none"
	}
	return ""
}

func startSingBox(content string, options *CoreOptions) error {
	if options.HomeDir != "" {
		if err := os.MkdirAll(options.HomeDir, 0o755); err != nil {
			return err
		}
	}
	prepared, err := prepareSingBoxJSON(content, options)
	if err != nil {
		return err
	}
	ctx := singBoxContext(options.HomeDir)
	boxOptions, err := parseSingBoxOptions(ctx, prepared)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	platform := &singBoxPlatform{vpn: options.Mode == ModeVPN, primary: true}
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, platform)
	instance, err := box.New(box.Options{
		Context:           ctx,
		Options:           boxOptions,
		PlatformLogWriter: singBoxLogWriter{},
	})
	if err != nil {
		cancel()
		return E.Cause(err, "create sing-box")
	}
	running := &singBoxRunning{ctx: ctx, cancel: cancel, instance: instance, platform: platform}
	singBoxAccess.Lock()
	singBoxCurrent = running
	singBoxAccess.Unlock()
	if err := instance.Start(); err != nil {
		return E.Cause(err, "start sing-box")
	}
	resetTrafficCounters()
	return nil
}

func stopSingBox() {
	singBoxAccess.Lock()
	running := singBoxCurrent
	singBoxCurrent = nil
	singBoxAccess.Unlock()
	if running == nil {
		return
	}
	if err := running.instance.Close(); err != nil {
		kiteLog(LogLevelWarning, "[sing-box] close: %v", err)
	}
	running.cancel()
}

func currentSingBox() *singBoxRunning {
	singBoxAccess.Lock()
	defer singBoxAccess.Unlock()
	return singBoxCurrent
}

// CheckSingBoxConfig parses and builds a sing-box profile without starting
// it.
func CheckSingBoxConfig(content string) error {
	ctx := singBoxContext("")
	options, err := parseSingBoxOptions(ctx, normalizeJSONC(content))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &singBoxPlatform{})
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err == nil {
		_ = instance.Close()
	}
	return err
}

type singBoxLogWriter struct{}

func (singBoxLogWriter) WriteMessage(level log.Level, message string) {
	var kiteLevel int32 = LogLevelInfo
	switch {
	case level <= log.LevelError:
		kiteLevel = LogLevelError
	case level == log.LevelWarn:
		kiteLevel = LogLevelWarning
	case level >= log.LevelDebug:
		kiteLevel = LogLevelDebug
	}
	kiteLog(kiteLevel, "[sing-box] %s", message)
}

// ---- platform interface ----

var _ adapter.PlatformInterface = (*singBoxPlatform)(nil)

// singBoxPlatform is the Android platform of one sing-box instance. primary
// marks the running instance: only its interface monitor takes the
// default-interface updates from Android, an offline delay test instance must
// not take them away from it.
type singBoxPlatform struct {
	vpn            bool
	primary        bool
	networkManager adapter.NetworkManager
	access         sync.Mutex
	myTunName      string
	myTunAddress   []netip.Addr
}

func (p *singBoxPlatform) Initialize(networkManager adapter.NetworkManager) error {
	p.networkManager = networkManager
	return nil
}

func (p *singBoxPlatform) UsePlatformAutoDetectInterfaceControl() bool { return true }

func (p *singBoxPlatform) AutoDetectInterfaceControl(fd int) error {
	return protectFd(fd)
}

func (p *singBoxPlatform) UsePlatformInterface() bool { return true }

func (p *singBoxPlatform) OpenInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	if !p.vpn {
		return nil, errors.New("tun inbound is only available in VPN mode")
	}
	platform := currentPlatform()
	if platform == nil {
		return nil, errors.New("platform not registered")
	}
	if len(options.IncludeUID) > 0 || len(options.ExcludeUID) > 0 || len(options.IncludeAndroidUser) > 0 {
		return nil, errors.New("tun: uid and android_user options are not supported, use per-app proxy instead")
	}
	routeRanges, err := options.BuildAutoRouteRanges(true)
	if err != nil {
		return nil, err
	}
	config := &TunConfig{
		Inet4Address:   joinPrefixes(options.Inet4Address),
		Inet6Address:   joinPrefixes(options.Inet6Address),
		MTU:            int32(options.MTU),
		AutoRoute:      options.AutoRoute,
		IncludePackage: strings.Join(options.IncludePackage, ","),
		ExcludePackage: strings.Join(options.ExcludePackage, ","),
	}
	var inet4Routes, inet6Routes []netip.Prefix
	for _, prefix := range routeRanges {
		if prefix.Addr().Is4() {
			inet4Routes = append(inet4Routes, prefix)
		} else {
			inet6Routes = append(inet6Routes, prefix)
		}
	}
	config.Inet4RouteRange = joinPrefixes(inet4Routes)
	config.Inet6RouteRange = joinPrefixes(inet6Routes)
	if dnsServers, err := options.DNSServerAddress(); err == nil {
		var servers []string
		for _, server := range dnsServers {
			servers = append(servers, server.String())
		}
		config.DNSServer = strings.Join(servers, ",")
	}
	if platformOptions.HTTPProxy != nil && platformOptions.HTTPProxy.Enabled {
		config.HTTPProxyServer = platformOptions.HTTPProxy.Server
		config.HTTPProxyPort = int32(platformOptions.HTTPProxy.ServerPort)
	}
	tunFd, err := platform.OpenTun(config)
	if err != nil {
		return nil, E.Cause(err, "open VpnService interface")
	}
	if name, err := getTunnelName(tunFd); err == nil {
		options.Name = name
	}
	if options.InterfaceMonitor != nil && options.Name != "" {
		options.InterfaceMonitor.RegisterMyInterface(options.Name)
	}
	// sing-box closes the descriptor it runs on; the VpnService descriptor
	// stays owned by the app, so sing-box gets a dup.
	dup, err := dupFd(int(tunFd))
	if err != nil {
		return nil, E.Cause(err, "dup tun descriptor")
	}
	options.FileDescriptor = dup
	p.access.Lock()
	p.myTunName = options.Name
	p.myTunAddress = nil
	for _, prefix := range append(append([]netip.Prefix{}, options.Inet4Address...), options.Inet6Address...) {
		p.myTunAddress = append(p.myTunAddress, prefix.Addr())
	}
	p.access.Unlock()
	return tun.New(*options)
}

func joinPrefixes(prefixes []netip.Prefix) string {
	values := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		values = append(values, prefix.String())
	}
	return strings.Join(values, ",")
}

func (p *singBoxPlatform) ProcessPlatformOptions(options option.TunPlatformOptions) error { return nil }

func (p *singBoxPlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }

func (p *singBoxPlatform) CreateDefaultInterfaceMonitor(logger logger.Logger) tun.DefaultInterfaceMonitor {
	return &singBoxInterfaceMonitor{platform: p, logger: logger}
}

func (p *singBoxPlatform) UsePlatformNetworkInterfaces() bool { return true }

func (p *singBoxPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	platform := currentPlatform()
	if platform == nil {
		return nil, errors.New("platform not registered")
	}
	interfaces := parseNetworkInterfaces(platform.NetworkInterfaces())
	p.access.Lock()
	myTun := p.myTunName
	p.access.Unlock()
	result := interfaces[:0]
	for _, item := range interfaces {
		if item.Name == myTun {
			continue
		}
		result = append(result, item)
	}
	return result, nil
}

// parseNetworkInterfaces reads KitePlatform.NetworkInterfaces output.
func parseNetworkInterfaces(value string) []adapter.NetworkInterface {
	var result []adapter.NetworkInterface
	seen := map[string]bool{}
	for _, line := range strings.Split(value, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "|")
		if len(fields) < 8 || fields[0] == "" || seen[fields[0]] {
			continue
		}
		index, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		mtu, _ := strconv.Atoi(fields[2])
		flags, _ := strconv.ParseUint(fields[3], 10, 32)
		var interfaceType C.InterfaceType
		switch fields[6] {
		case "wifi":
			interfaceType = C.InterfaceTypeWIFI
		case "cellular":
			interfaceType = C.InterfaceTypeCellular
		case "ethernet":
			interfaceType = C.InterfaceTypeEthernet
		default:
			interfaceType = C.InterfaceTypeOther
		}
		seen[fields[0]] = true
		result = append(result, adapter.NetworkInterface{
			Interface: control.Interface{
				Index:     index,
				MTU:       mtu,
				Name:      fields[0],
				Flags:     net.Flags(flags),
				Addresses: parsePrefixes(fields[4]),
			},
			Type:       interfaceType,
			DNSServers: splitList(fields[5]),
			Expensive:  fields[7] == "1" || fields[7] == "true",
		})
	}
	return result
}

func (p *singBoxPlatform) UnderNetworkExtension() bool               { return false }
func (p *singBoxPlatform) NetworkExtensionIncludeAllNetworks() bool  { return false }
func (p *singBoxPlatform) ClearDNSCache()                            {}
func (p *singBoxPlatform) RequestPermissionForWIFIState() error      { return nil }
func (p *singBoxPlatform) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	return adapter.WIFIState{}
}
func (p *singBoxPlatform) UsePlatformConnectionOwnerFinder() bool { return true }

func (p *singBoxPlatform) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	network := "tcp"
	if request.IpProtocol == 17 {
		network = "udp"
	}
	src, err1 := netip.ParseAddr(request.SourceAddress)
	dst, err2 := netip.ParseAddr(request.DestinationAddress)
	if err1 != nil || err2 != nil {
		return nil, errors.New("invalid connection address")
	}
	uid := findOwnerUid(network, netip.AddrPortFrom(src, uint16(request.SourcePort)), netip.AddrPortFrom(dst, uint16(request.DestinationPort)))
	if uid < 0 {
		return nil, errors.New("connection owner not found")
	}
	owner := &adapter.ConnectionOwner{UserId: uid}
	if name := packageNameByUid(uid); name != "" {
		owner.AndroidPackageNames = []string{name}
	}
	return owner, nil
}

func (p *singBoxPlatform) UsePlatformWIFIMonitor() bool  { return false }
func (p *singBoxPlatform) UsePlatformNotification() bool { return false }
func (p *singBoxPlatform) SendNotification(notification *adapter.Notification) error {
	return nil
}
func (p *singBoxPlatform) CancelNotification(identifier string, typeID int32) error { return nil }

func (p *singBoxPlatform) MyInterfaceAddress() []netip.Addr {
	p.access.Lock()
	defer p.access.Unlock()
	return p.myTunAddress
}

func (p *singBoxPlatform) UsePlatformNeighborResolver() bool { return false }
func (p *singBoxPlatform) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return os.ErrInvalid
}
func (p *singBoxPlatform) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return nil
}
func (p *singBoxPlatform) UsePlatformShell() bool     { return false }
func (p *singBoxPlatform) CheckPlatformShell() error  { return os.ErrInvalid }
func (p *singBoxPlatform) OpenShellSession(user *adapter.PlatformUser, command string, env []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}
func (p *singBoxPlatform) LookupUser(username string) (*adapter.PlatformUser, error) {
	return nil, os.ErrInvalid
}
func (p *singBoxPlatform) LookupSFTPServer() (string, error)     { return "", os.ErrInvalid }
func (p *singBoxPlatform) ReadSystemSSHHostKey() ([]byte, error) { return nil, os.ErrInvalid }
func (p *singBoxPlatform) TailscaleHostname() string             { return "" }
func (p *singBoxPlatform) UsePlatformBridge() bool               { return false }
func (p *singBoxPlatform) CreateBridge(options adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, os.ErrInvalid
}

// ---- default interface monitor, fed from Android ConnectivityManager ----

var _ tun.DefaultInterfaceMonitor = (*singBoxInterfaceMonitor)(nil)

type singBoxInterfaceMonitor struct {
	platform         *singBoxPlatform
	logger           logger.Logger
	access           sync.Mutex
	callbacks        list.List[tun.DefaultInterfaceUpdateCallback]
	defaultInterface *control.Interface
	myInterfaces     []string
}

func (m *singBoxInterfaceMonitor) Start() error {
	if m.platform.primary {
		singBoxAccess.Lock()
		singBoxMonitor = m
		singBoxAccess.Unlock()
	}
	if name, index, ok := lastDefaultInterface(); ok {
		m.update(name, index)
	}
	return nil
}

func (m *singBoxInterfaceMonitor) Close() error {
	singBoxAccess.Lock()
	if singBoxMonitor == m {
		singBoxMonitor = nil
	}
	singBoxAccess.Unlock()
	return nil
}

func (m *singBoxInterfaceMonitor) DefaultInterface() *control.Interface {
	m.access.Lock()
	defer m.access.Unlock()
	return m.defaultInterface
}

func (m *singBoxInterfaceMonitor) OverrideAndroidVPN() bool { return false }
func (m *singBoxInterfaceMonitor) AndroidVPNEnabled() bool  { return false }

func (m *singBoxInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.access.Lock()
	defer m.access.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *singBoxInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.access.Lock()
	defer m.access.Unlock()
	m.callbacks.Remove(element)
}

func (m *singBoxInterfaceMonitor) RegisterMyInterface(interfaceName string) {
	m.access.Lock()
	defer m.access.Unlock()
	m.myInterfaces = append(m.myInterfaces, interfaceName)
}

func (m *singBoxInterfaceMonitor) MyInterfaces() []string {
	m.access.Lock()
	defer m.access.Unlock()
	return m.myInterfaces
}

func (m *singBoxInterfaceMonitor) update(name string, index int32) {
	networkManager := m.platform.networkManager
	if networkManager != nil {
		if err := networkManager.UpdateInterfaces(); err != nil {
			m.logger.Error(E.Cause(err, "update interfaces"))
		}
	}
	m.access.Lock()
	if index < 0 {
		m.defaultInterface = nil
		callbacks := m.callbacks.Array()
		m.access.Unlock()
		for _, callback := range callbacks {
			callback(nil, 0)
		}
		return
	}
	var newInterface *control.Interface
	if networkManager != nil {
		if found, err := networkManager.InterfaceFinder().ByIndex(int(index)); err == nil {
			newInterface = found
		}
	}
	if newInterface == nil {
		newInterface = &control.Interface{Name: name, Index: int(index)}
	}
	old := m.defaultInterface
	if old != nil && old.Name == newInterface.Name && old.Index == newInterface.Index {
		m.access.Unlock()
		return
	}
	m.defaultInterface = newInterface
	callbacks := m.callbacks.Array()
	m.access.Unlock()
	for _, callback := range callbacks {
		callback(newInterface, 0)
	}
}

var (
	defaultInterfaceAccess sync.Mutex
	defaultInterfaceName   string
	defaultInterfaceIndex  int32 = -1
	defaultInterfaceKnown  bool
)

func lastDefaultInterface() (string, int32, bool) {
	defaultInterfaceAccess.Lock()
	defer defaultInterfaceAccess.Unlock()
	return defaultInterfaceName, defaultInterfaceIndex, defaultInterfaceKnown
}

// UpdateDefaultInterface tells sing-box which interface carries the default
// route (index -1 when there is none). The app calls it whenever Android's
// default network changes.
func UpdateDefaultInterface(name string, index int32) {
	defaultInterfaceAccess.Lock()
	defaultInterfaceName = name
	defaultInterfaceIndex = index
	defaultInterfaceKnown = true
	defaultInterfaceAccess.Unlock()
	singBoxAccess.Lock()
	monitor := singBoxMonitor
	singBoxAccess.Unlock()
	if monitor != nil {
		go monitor.update(name, index)
	}
}

func singBoxOutboundManager() (adapter.OutboundManager, error) {
	running := currentSingBox()
	if running == nil {
		return nil, errors.New("sing-box is not running")
	}
	manager := service.FromContext[adapter.OutboundManager](running.ctx)
	if manager == nil {
		return nil, errors.New("sing-box outbound manager unavailable")
	}
	return manager, nil
}

func singBoxTestOutbound(manager adapter.OutboundManager, tag string) (adapter.Outbound, error) {
	if tag != "" {
		if outbound, ok := manager.Outbound(tag); ok {
			return outbound, nil
		}
	}
	outbound := manager.Default()
	if outbound == nil {
		return nil, fmt.Errorf("outbound %q not found", tag)
	}
	return outbound, nil
}
