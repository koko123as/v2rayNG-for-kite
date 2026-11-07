package libv2ray

// Delay tests, traffic counters, groups, config detection and versions for
// mihomo and sing-box.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	mihomoOutboundGroup "github.com/metacubex/mihomo/adapter/outboundgroup"
	mihomoCacheFile "github.com/metacubex/mihomo/component/profile/cachefile"
	mihomoConfig "github.com/metacubex/mihomo/config"
	mihomoConstant "github.com/metacubex/mihomo/constant"
	mihomoInner "github.com/metacubex/mihomo/listener/inner"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	mihomoStatistic "github.com/metacubex/mihomo/tunnel/statistic"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	sbConstant "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/service"
	"gopkg.in/yaml.v3"
)

const defaultDelayURL = "https://www.gstatic.com/generate_204"

func delayTimeout(timeoutMs int32) time.Duration {
	if timeoutMs <= 0 {
		return 12 * time.Second
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

// httpDelay measures the best of two GETs to url over dial.
func httpDelay(ctx context.Context, url string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (int64, error) {
	if url == "" {
		url = defaultDelayURL
	}
	transport := &http.Transport{
		TLSHandshakeTimeout: 6 * time.Second,
		DialContext:         dial,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	best := int64(-1)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return -1, err
		}
		start := time.Now()
		response, err := client.Do(request)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
			lastErr = fmt.Errorf("invalid status: %s", response.Status)
			continue
		}
		elapsed := time.Since(start).Milliseconds()
		if best < 0 || elapsed < best {
			best = elapsed
		}
	}
	if best < 0 {
		if lastErr == nil {
			lastErr = errors.New("delay test failed")
		}
		return -1, lastErr
	}
	return best, nil
}

// MeasureKiteDelay measures the delay through the running mihomo or sing-box,
// following its rules (mihomo) or its "proxy" / default outbound (sing-box).
func MeasureKiteDelay(url string, timeoutMs int32) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), delayTimeout(timeoutMs))
	defer cancel()
	switch RunningKiteCore() {
	case CoreMihomo:
		return httpDelay(ctx, url, func(ctx context.Context, network, addr string) (net.Conn, error) {
			return mihomoInner.HandleTcp(mihomoTunnel.Tunnel, addr, "")
		})
	case CoreSingBox:
		manager, err := singBoxOutboundManager()
		if err != nil {
			return -1, err
		}
		outbound, err := singBoxTestOutbound(manager, "proxy")
		if err != nil {
			return -1, err
		}
		delay, err := urltest.URLTest(ctx, urlOrDefault(url), outbound)
		if err != nil {
			return -1, err
		}
		return int64(delay), nil
	}
	return -1, errors.New("no core running")
}

func urlOrDefault(url string) string {
	if url == "" {
		return defaultDelayURL
	}
	return url
}

// MeasureKiteOutboundDelay tests a profile without running it: the outbound
// (or group) named target, "proxy" by default.
func MeasureKiteOutboundDelay(core string, content string, target string, url string, timeoutMs int32, homeDir string) (int64, error) {
	if target == "" {
		target = "proxy"
	}
	ctx, cancel := context.WithTimeout(context.Background(), delayTimeout(timeoutMs))
	defer cancel()
	switch core {
	case CoreMihomo:
		return measureMihomoOffline(ctx, content, target, url)
	case CoreSingBox:
		return measureSingBoxOffline(ctx, content, target, url, homeDir)
	}
	return -1, fmt.Errorf("unknown core: %s", core)
}

func measureMihomoOffline(ctx context.Context, content string, target string, url string) (int64, error) {
	raw, err := mihomoConfig.UnmarshalRawConfig([]byte(content))
	if err != nil {
		return -1, err
	}
	// Only proxies, groups and providers matter for the test.
	raw.Rule = nil
	raw.SubRules = nil
	raw.RuleProvider = nil
	raw.Listeners = nil
	raw.Tun.Enable = false
	raw.DNS.Enable = false
	raw.Port, raw.SocksPort, raw.MixedPort, raw.RedirPort, raw.TProxyPort = 0, 0, 0, 0, 0
	raw.ExternalController = ""
	raw.ExternalControllerTLS = ""
	raw.ExternalControllerUnix = ""
	raw.ExternalControllerPipe = ""
	config, err := mihomoConfig.ParseRawConfig(raw)
	if err != nil {
		return -1, err
	}
	for _, provider := range config.Providers {
		_ = provider.Initial()
	}
	proxy, ok := config.Proxies[target]
	if !ok {
		proxy = firstMihomoProxy(raw, config.Proxies)
		if proxy == nil {
			return -1, fmt.Errorf("proxy %q not found", target)
		}
	}
	proxy = resolveMihomoGroupMember(proxy, 0)
	delay, err := proxy.URLTest(ctx, urlOrDefault(url), nil)
	if err != nil {
		return -1, err
	}
	return int64(delay), nil
}

func firstMihomoProxy(raw *mihomoConfig.RawConfig, proxies map[string]mihomoConstant.Proxy) mihomoConstant.Proxy {
	for _, group := range raw.ProxyGroup {
		if name, _ := group["name"].(string); name != "" {
			if proxy, ok := proxies[name]; ok {
				return proxy
			}
		}
	}
	for _, item := range raw.Proxy {
		if name, _ := item["name"].(string); name != "" {
			if proxy, ok := proxies[name]; ok {
				return proxy
			}
		}
	}
	return nil
}

// resolveMihomoGroupMember follows a group down to a concrete proxy for an
// offline test, where health checks have not chosen anything yet.
func resolveMihomoGroupMember(proxy mihomoConstant.Proxy, depth int) mihomoConstant.Proxy {
	if depth > 8 {
		return proxy
	}
	group, ok := proxy.Adapter().(mihomoOutboundGroup.ProxyGroup)
	if !ok {
		return proxy
	}
	members := group.Proxies()
	if len(members) == 0 {
		return proxy
	}
	return resolveMihomoGroupMember(members[0], depth+1)
}

func measureSingBoxOffline(ctx context.Context, content string, target string, url string, homeDir string) (int64, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(content), &root); err != nil {
		return -1, err
	}
	root["inbounds"] = []any{}
	delete(root, "experimental")
	delete(root, "services")
	if logOptions, ok := root["log"].(map[string]any); ok {
		delete(logOptions, "output")
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return -1, err
	}
	prepared, err := prepareSingBoxGeoRuleSets(string(encoded), "", homeDir)
	if err != nil {
		// Geo rule-sets do not matter for a delay test; drop the rules.
		route, _ := root["route"].(map[string]any)
		if route != nil {
			delete(route, "rule_set")
			delete(route, "rules")
		}
		dns, _ := root["dns"].(map[string]any)
		if dns != nil {
			delete(dns, "rules")
		}
		encoded, _ = json.Marshal(root)
		prepared = string(encoded)
	}
	boxCtx := singBoxContext("")
	options, err := parseSingBoxOptions(boxCtx, prepared)
	if err != nil {
		return -1, err
	}
	boxCtx, cancel := context.WithCancel(boxCtx)
	defer cancel()
	boxCtx = service.ContextWith[adapter.PlatformInterface](boxCtx, &singBoxPlatform{})
	instance, err := box.New(box.Options{Context: boxCtx, Options: options, PlatformLogWriter: singBoxLogWriter{}})
	if err != nil {
		return -1, err
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		return -1, err
	}
	manager := service.FromContext[adapter.OutboundManager](boxCtx)
	outbound, err := singBoxTestOutbound(manager, target)
	if err != nil {
		return -1, err
	}
	delay, err := urltest.URLTest(ctx, urlOrDefault(url), outbound)
	if err != nil {
		return -1, err
	}
	return int64(delay), nil
}

// ---- traffic ----

var (
	trafficAccess      sync.Mutex
	trafficLastUp      int64
	trafficLastDown    int64
	trafficLastPerConn = map[string][2]int64{}
)

func resetTrafficCounters() {
	trafficAccess.Lock()
	defer trafficAccess.Unlock()
	trafficLastUp, trafficLastDown = 0, 0
	trafficLastPerConn = map[string][2]int64{}
}

// QueryKiteTrafficStats returns traffic since the previous call in the
// format of CoreController.QueryAllOutboundTrafficStats:
// "proxy,uplink,n;proxy,downlink,n;direct,uplink,n;direct,downlink,n;".
// Bytes of connections that went out directly are reported as "direct",
// everything else as "proxy".
func QueryKiteTrafficStats() string {
	type connTotals struct {
		id     string
		up     int64
		down   int64
		direct bool
	}
	var up, down int64
	var connections []connTotals
	switch RunningKiteCore() {
	case CoreMihomo:
		up, down = mihomoStatistic.DefaultManager.Total()
		mihomoStatistic.DefaultManager.Range(func(tracker mihomoStatistic.Tracker) bool {
			info := tracker.Info()
			direct := false
			if len(info.Chain) > 0 {
				last := info.Chain[len(info.Chain)-1]
				direct = last == "DIRECT"
			}
			connections = append(connections, connTotals{id: info.UUID.String(), up: info.UploadTotal.Load(), down: info.DownloadTotal.Load(), direct: direct})
			return true
		})
	case CoreSingBox:
		running := currentSingBox()
		if running == nil {
			return ""
		}
		manager := service.PtrFromContext[trafficcontrol.Manager](running.ctx)
		if manager == nil {
			return ""
		}
		up, down = manager.Total()
		for _, connection := range manager.Connections() {
			direct := connection.OutboundType == sbConstant.TypeDirect
			connections = append(connections, connTotals{id: connection.ID.String(), up: connection.Upload.Load(), down: connection.Download.Load(), direct: direct})
		}
	default:
		return ""
	}
	trafficAccess.Lock()
	defer trafficAccess.Unlock()
	deltaUp := up - trafficLastUp
	deltaDown := down - trafficLastDown
	if deltaUp < 0 || deltaDown < 0 {
		deltaUp, deltaDown = up, down
	}
	trafficLastUp, trafficLastDown = up, down
	var directUp, directDown int64
	current := make(map[string][2]int64, len(connections))
	for _, connection := range connections {
		last := trafficLastPerConn[connection.id]
		current[connection.id] = [2]int64{connection.up, connection.down}
		if connection.direct {
			directUp += max64(connection.up-last[0], 0)
			directDown += max64(connection.down-last[1], 0)
		}
	}
	trafficLastPerConn = current
	directUp = min64(directUp, deltaUp)
	directDown = min64(directDown, deltaDown)
	var builder strings.Builder
	write := func(tag string, direction string, value int64) {
		if value <= 0 {
			return
		}
		builder.WriteString(tag + "," + direction + "," + strconv.FormatInt(value, 10) + ";")
	}
	write("proxy", "uplink", deltaUp-directUp)
	write("proxy", "downlink", deltaDown-directDown)
	write("direct", "uplink", directUp)
	write("direct", "downlink", directDown)
	return builder.String()
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// ---- groups ----

type kiteGroup struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Now        string   `json:"now"`
	Selectable bool     `json:"selectable"`
	All        []string `json:"all"`
}

// GetKiteGroups returns the running core's proxy groups as JSON:
// [{"name","type","now","selectable","all":[...]}].
func GetKiteGroups() string {
	var groups []kiteGroup
	switch RunningKiteCore() {
	case CoreMihomo:
		proxies := mihomoTunnel.Proxies()
		names := make([]string, 0, len(proxies))
		for name := range proxies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			proxy := proxies[name]
			group, ok := proxy.Adapter().(mihomoOutboundGroup.ProxyGroup)
			if !ok || name == "GLOBAL" {
				continue
			}
			item := kiteGroup{Name: name, Type: strings.ToLower(proxy.Type().String()), Now: group.Now(), Selectable: proxy.Type() == mihomoConstant.Selector}
			for _, member := range group.Proxies() {
				item.All = append(item.All, member.Name())
			}
			groups = append(groups, item)
		}
	case CoreSingBox:
		manager, err := singBoxOutboundManager()
		if err != nil {
			return "[]"
		}
		for _, outbound := range manager.Outbounds() {
			outboundGroup, ok := outbound.(adapter.OutboundGroup)
			if !ok {
				continue
			}
			item := kiteGroup{Name: outbound.Tag(), Type: outbound.Type(), All: outboundGroup.All()}
			if selected := outboundGroup.Selected("tcp"); selected != nil {
				item.Now = selected.Tag()
			}
			_, item.Selectable = outbound.(*group.Selector)
			groups = append(groups, item)
		}
	}
	if groups == nil {
		return "[]"
	}
	encoded, _ := json.Marshal(groups)
	return string(encoded)
}

// SelectKiteOutbound selects name in the selector group of the running core.
func SelectKiteOutbound(groupName string, name string) error {
	switch RunningKiteCore() {
	case CoreMihomo:
		proxy, ok := mihomoTunnel.Proxies()[groupName]
		if !ok {
			return fmt.Errorf("group %q not found", groupName)
		}
		selectable, ok := proxy.Adapter().(mihomoOutboundGroup.SelectAble)
		if !ok || proxy.Type() != mihomoConstant.Selector {
			return fmt.Errorf("group %q is not selectable", groupName)
		}
		if err := selectable.Set(name); err != nil {
			return err
		}
		mihomoCacheFile.Cache().SetSelected(groupName, name)
		return nil
	case CoreSingBox:
		manager, err := singBoxOutboundManager()
		if err != nil {
			return err
		}
		outbound, ok := manager.Outbound(groupName)
		if !ok {
			return fmt.Errorf("group %q not found", groupName)
		}
		selector, ok := outbound.(*group.Selector)
		if !ok {
			return fmt.Errorf("group %q is not selectable", groupName)
		}
		if !selector.SelectOutbound(name) {
			return fmt.Errorf("%q is not in group %q", name, groupName)
		}
		return nil
	}
	return errors.New("no core running")
}

// MeasureKiteProxyDelay tests one proxy/outbound of the running core by name.
func MeasureKiteProxyDelay(name string, url string, timeoutMs int32) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), delayTimeout(timeoutMs))
	defer cancel()
	switch RunningKiteCore() {
	case CoreMihomo:
		proxy, ok := mihomoTunnel.Proxies()[name]
		if !ok {
			return -1, fmt.Errorf("proxy %q not found", name)
		}
		delay, err := proxy.URLTest(ctx, urlOrDefault(url), nil)
		if err != nil {
			return -1, err
		}
		return int64(delay), nil
	case CoreSingBox:
		manager, err := singBoxOutboundManager()
		if err != nil {
			return -1, err
		}
		outbound, ok := manager.Outbound(name)
		if !ok {
			return -1, fmt.Errorf("outbound %q not found", name)
		}
		delay, err := urltest.URLTest(ctx, urlOrDefault(url), outbound)
		if err != nil {
			return -1, err
		}
		return int64(delay), nil
	}
	return -1, errors.New("no core running")
}

// ---- config detection ----

// DetectCoreConfig tells which core a full configuration belongs to:
// "mihomo" (Clash YAML), "sing-box" (JSON with typed outbounds), "xray"
// (JSON with protocol outbounds/inbounds) or "" (not a full configuration,
// e.g. share links or a Base64 subscription).
func DetectCoreConfig(content string) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(content, "\ufeff"))
	if trimmed == "" {
		return ""
	}
	// JSONC may open with a comment before the root object.
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
		trimmed = strings.TrimSpace(removeJSONComments(trimmed))
	}
	if strings.HasPrefix(trimmed, "{") {
		var root map[string]json.RawMessage
		if json.Unmarshal([]byte(normalizeJSONC(trimmed)), &root) != nil {
			return ""
		}
		for _, key := range []string{"outbounds", "inbounds"} {
			var items []map[string]any
			if raw, ok := root[key]; ok && json.Unmarshal(raw, &items) == nil {
				for _, item := range items {
					if _, ok := item["protocol"]; ok {
						return CoreXray
					}
				}
				for _, item := range items {
					if _, ok := item["type"]; ok {
						return CoreSingBox
					}
				}
			}
		}
		var endpoints []json.RawMessage
		if raw, ok := root["endpoints"]; ok && json.Unmarshal(raw, &endpoints) == nil && len(endpoints) > 0 {
			return CoreSingBox
		}
		var schema string
		if raw, ok := root["$schema"]; ok && json.Unmarshal(raw, &schema) == nil && strings.Contains(strings.ToLower(schema), "sing-box") {
			return CoreSingBox
		}
		if _, ok := root["routing"]; ok {
			return CoreXray
		}
		if _, ok := root["route"]; ok {
			return CoreSingBox
		}
		// sing-box 1.12+ DNS servers are objects with "type".
		var dns struct {
			Servers []json.RawMessage `json:"servers"`
		}
		if raw, ok := root["dns"]; ok && json.Unmarshal(raw, &dns) == nil {
			for _, server := range dns.Servers {
				var item map[string]any
				if json.Unmarshal(server, &item) == nil {
					if _, ok := item["type"]; ok {
						return CoreSingBox
					}
				}
			}
		}
		return ""
	}
	if strings.HasPrefix(trimmed, "[") {
		return ""
	}
	var root map[string]any
	if yaml.Unmarshal([]byte(trimmed), &root) != nil || root == nil {
		return ""
	}
	for _, key := range []string{"proxies", "proxy-providers", "proxy-groups"} {
		if _, ok := root[key]; ok {
			return CoreMihomo
		}
	}
	return ""
}

// CheckCoreConfig validates a full configuration for core without starting
// it. Xray configurations are only checked to be JSON.
func CheckCoreConfig(core string, content string) error {
	switch core {
	case CoreMihomo:
		return CheckMihomoConfig(content)
	case CoreSingBox:
		return CheckSingBoxConfig(content)
	case CoreXray:
		var root map[string]any
		return json.Unmarshal([]byte(content), &root)
	}
	return fmt.Errorf("unknown core: %s", core)
}

// ---- versions ----

func moduleVersion(path string) string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, module := range info.Deps {
			if module.Path == path {
				if module.Replace != nil && module.Replace.Version != "" {
					return strings.TrimPrefix(module.Replace.Version, "v")
				}
				return strings.TrimPrefix(module.Version, "v")
			}
		}
	}
	return ""
}

// MihomoVersion returns the embedded mihomo version.
func MihomoVersion() string {
	if version := moduleVersion("github.com/metacubex/mihomo"); version != "" {
		return version
	}
	return strings.TrimPrefix(mihomoConstant.Version, "v")
}

// SingBoxVersion returns the embedded sing-box version.
func SingBoxVersion() string {
	if version := moduleVersion("github.com/sagernet/sing-box"); version != "" {
		return version
	}
	return sbConstant.Version
}
