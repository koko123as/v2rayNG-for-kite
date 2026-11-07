package libv2ray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mihomoConfig "github.com/metacubex/mihomo/config"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

const testMihomoConfig = `
mixed-port: 7890
external-controller: 127.0.0.1:9090
tun:
  enable: true
  auto-route: true
proxies:
  - name: node-a
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: secret
proxy-groups:
  - name: proxy
    type: select
    proxies: [node-a, DIRECT]
rules:
  - MATCH,proxy
`

const testSingBoxConfig = `{
  "log": {"level": "info", "output": "box.log"},
  "inbounds": [{"type": "tun", "tag": "user-tun", "address": ["172.19.0.1/30"]}],
  "outbounds": [
    {"type": "shadowsocks", "tag": "node-a", "server": "1.2.3.4", "server_port": 8388, "method": "aes-128-gcm", "password": "secret"},
    {"type": "selector", "tag": "proxy", "outbounds": ["node-a", "direct"]},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "proxy", "rules": [{"ip_is_private": true, "outbound": "direct"}]},
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}}
}`

func TestDetectCoreConfig(t *testing.T) {
	cases := map[string]string{
		testMihomoConfig:  CoreMihomo,
		testSingBoxConfig: CoreSingBox,
		`{"outbounds":[{"protocol":"vless","settings":{}}]}`: CoreXray,
		`{"inbounds":[{"protocol":"socks"}],"outbounds":[]}`:  CoreXray,
		"vless://uuid@example.com:443#name":                   "",
		"dmxlc3M6Ly91dWlkQGV4YW1wbGUuY29tOjQ0Mw==":            "",
		"":                         "",
		`[{"remarks":"a"}]`:        "",
		"just: yaml\nwithout: proxies": "",
	}
	for content, expected := range cases {
		if got := DetectCoreConfig(content); got != expected {
			t.Errorf("DetectCoreConfig(%q) = %q, want %q", firstLine(content), got, expected)
		}
	}
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return value[:index]
	}
	return value
}

func TestPrepareMihomoRawVPN(t *testing.T) {
	raw, err := mihomoConfig.UnmarshalRawConfig([]byte(testMihomoConfig))
	if err != nil {
		t.Fatal(err)
	}
	prepareMihomoRaw(raw, &CoreOptions{Mode: ModeVPN, TunFd: 10, TunInet4: "10.10.14.1/30", TunInet6: "fc00::10:10:14:1/126", TunMTU: 1500, LogLevel: "debug"})
	if raw.MixedPort != 0 || raw.ExternalController != "" {
		t.Fatalf("ports/controller not cleared: mixed=%d controller=%q", raw.MixedPort, raw.ExternalController)
	}
	if !raw.Tun.Enable || raw.Tun.AutoRoute || raw.Tun.AutoDetectInterface || raw.Tun.AutoRedirect {
		t.Fatalf("unexpected tun settings: %+v", raw.Tun)
	}
	if raw.Tun.MTU != 1500 || len(raw.Tun.Inet6Address) != 1 {
		t.Fatalf("mtu/inet6 not applied: %+v", raw.Tun)
	}
	if len(raw.Tun.DNSHijack) == 0 {
		t.Fatal("dns hijack missing")
	}
}

func TestPrepareMihomoRawRootAndProxy(t *testing.T) {
	raw, err := mihomoConfig.UnmarshalRawConfig([]byte(testMihomoConfig))
	if err != nil {
		t.Fatal(err)
	}
	prepareMihomoRaw(raw, &CoreOptions{Mode: ModeRoot, TProxyPort: 12345, RedirPort: 12346, DNSPort: 1053, MixedPort: 10808, MixedUser: "u", MixedPass: "p"})
	if raw.Tun.Enable {
		t.Fatal("tun must be off in root mode")
	}
	if raw.TProxyPort != 12345 || raw.RedirPort != 12346 || raw.MixedPort != 10808 {
		t.Fatalf("ports not applied: %d %d %d", raw.TProxyPort, raw.RedirPort, raw.MixedPort)
	}
	if raw.DNS.Listen != "127.0.0.1:1053" || !raw.DNS.Enable {
		t.Fatalf("dns listen = %q", raw.DNS.Listen)
	}
	if len(raw.Authentication) != 1 || raw.Authentication[0] != "u:p" {
		t.Fatalf("authentication = %v", raw.Authentication)
	}
	// The prepared raw config must still parse.
	if _, err := mihomoConfig.ParseRawConfig(raw); err != nil {
		t.Fatal(err)
	}
}

func decodeJSON(t *testing.T, content string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal([]byte(content), &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestPrepareSingBoxVPN(t *testing.T) {
	prepared, err := prepareSingBoxJSON(testSingBoxConfig, &CoreOptions{Mode: ModeVPN, TunInet4: "10.10.14.1/30", TunInet6: "fc00::1/126", IPv6: true, TunMTU: 1500, TunBypassLan: true, LogLevel: "warning", HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	root := decodeJSON(t, prepared)
	inbounds := root["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("inbounds = %v", inbounds)
	}
	tunInbound := inbounds[0].(map[string]any)
	if tunInbound["type"] != "tun" || tunInbound["tag"] != singBoxTunTag || tunInbound["auto_route"] != true {
		t.Fatalf("tun inbound = %v", tunInbound)
	}
	if len(tunInbound["address"].([]any)) != 2 || tunInbound["route_exclude_address"] == nil {
		t.Fatalf("tun address/exclude = %v", tunInbound)
	}
	route := root["route"].(map[string]any)
	rules := route["rules"].([]any)
	if rules[0].(map[string]any)["action"] != "sniff" || rules[1].(map[string]any)["action"] != "hijack-dns" {
		t.Fatalf("sniff/hijack rules not first: %v", rules)
	}
	if route["auto_detect_interface"] != true {
		t.Fatal("auto_detect_interface must be on in VPN mode")
	}
	experimental := root["experimental"].(map[string]any)
	if _, ok := experimental["clash_api"]; ok {
		t.Fatal("clash_api must be removed")
	}
	logOptions := root["log"].(map[string]any)
	if logOptions["level"] != "warn" || logOptions["output"] != nil {
		t.Fatalf("log = %v", logOptions)
	}
	if err := CheckSingBoxConfig(prepared); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareSingBoxRootAndProxy(t *testing.T) {
	prepared, err := prepareSingBoxJSON(testSingBoxConfig, &CoreOptions{Mode: ModeRoot, TProxyPort: 12345, RedirPort: 12346, DNSPort: 1053})
	if err != nil {
		t.Fatal(err)
	}
	root := decodeJSON(t, prepared)
	var types []string
	for _, inbound := range root["inbounds"].([]any) {
		types = append(types, inbound.(map[string]any)["type"].(string))
	}
	if strings.Join(types, ",") != "tproxy,redirect,direct" {
		t.Fatalf("root inbounds = %v", types)
	}
	if _, ok := root["route"].(map[string]any)["auto_detect_interface"]; ok {
		t.Fatal("auto_detect_interface must be off in root mode")
	}
	if err := CheckSingBoxConfig(prepared); err != nil {
		t.Fatal(err)
	}

	prepared, err = prepareSingBoxJSON(testSingBoxConfig, &CoreOptions{Mode: ModeProxy, MixedPort: 10808, MixedUser: "u", MixedPass: "p"})
	if err != nil {
		t.Fatal(err)
	}
	root = decodeJSON(t, prepared)
	inbounds := root["inbounds"].([]any)
	if len(inbounds) != 1 || inbounds[0].(map[string]any)["type"] != "mixed" || inbounds[0].(map[string]any)["users"] == nil {
		t.Fatalf("proxy inbounds = %v", inbounds)
	}
	if err := CheckSingBoxConfig(prepared); err != nil {
		t.Fatal(err)
	}
}

func writeTestGeoFiles(t *testing.T, dir string) {
	t.Helper()
	site := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		Code: "TEST",
		Domain: []*geodata.Domain{
			{Type: geodata.Domain_Domain, Value: "example.com"},
			{Type: geodata.Domain_Full, Value: "full.example.org"},
			{Type: geodata.Domain_Substr, Value: "keyword"},
			{Type: geodata.Domain_Regex, Value: `^re\.example$`},
			{Type: geodata.Domain_Domain, Value: "cn.example.com", Attribute: []*geodata.Domain_Attribute{{Key: "cn"}}},
		},
	}}}
	ip := &geodata.GeoIPList{Entry: []*geodata.GeoIP{{
		Code: "TEST",
		Cidr: []*geodata.CIDR{{Ip: []byte{10, 0, 0, 0}, Prefix: 8}, {Ip: make([]byte, 16), Prefix: 7}},
	}}}
	for name, message := range map[string]proto.Message{"geosite.dat": site, "geoip.dat": ip} {
		content, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGeoRuleSets(t *testing.T) {
	assets := t.TempDir()
	home := t.TempDir()
	writeTestGeoFiles(t, assets)

	ref, ok := parseGeoRef("kitegeo:site:geosite.dat:test")
	if !ok {
		t.Fatal("parse failed")
	}
	output, err := buildSingBoxGeoRuleSet(assets, home, ref)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	ruleSet, err := srs.Read(file, false)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	rule := ruleSet.Options.Rules[0].DefaultOptions
	if rule.DomainMatcher == nil || len(rule.DomainKeyword) != 1 || len(rule.DomainRegex) != 1 {
		t.Fatalf("unexpected rule: %+v", rule)
	}
	for domain, expected := range map[string]bool{"www.example.com": true, "example.com": true, "full.example.org": true, "x.full.example.org": false, "other.org": false} {
		if rule.DomainMatcher.Match(domain) != expected {
			t.Errorf("match %s != %v", domain, expected)
		}
	}

	attrRef, _ := parseGeoRef("kitegeo:site:geosite.dat:test@cn")
	entries, err := loadGeoEntries(assets, attrRef)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries.suffix) != 1 || entries.suffix[0] != "cn.example.com" {
		t.Fatalf("attribute filter: %+v", entries)
	}

	ipRef, _ := parseGeoRef("kitegeo:ip:geoip.dat:test")
	providerPath, err := buildMihomoGeoProvider(assets, home, ipRef)
	if err != nil {
		t.Fatal(err)
	}
	provider, _ := os.ReadFile(providerPath)
	if !strings.Contains(string(provider), "IP-CIDR,10.0.0.0/8,no-resolve") || !strings.Contains(string(provider), "IP-CIDR6,::/7,no-resolve") {
		t.Fatalf("provider = %s", provider)
	}

	if _, err := loadGeoEntries(assets, geoRef{kind: "site", file: "geosite.dat", code: "missing"}); err == nil {
		t.Fatal("missing code must fail")
	}

	content := `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rule_set":[{"type":"local","tag":"geosite-test","format":"binary","path":"kitegeo:site:geosite.dat:test"}],"rules":[{"rule_set":"geosite-test","outbound":"direct"}]}}`
	prepared, err := prepareSingBoxGeoRuleSets(content, assets, home)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prepared, kiteGeoPrefix) {
		t.Fatalf("reference not replaced: %s", prepared)
	}
	if err := CheckSingBoxConfig(prepared); err != nil {
		t.Fatal(err)
	}

	raw, err := mihomoConfig.UnmarshalRawConfig([]byte("proxies: []\nrule-providers:\n  geoip-test:\n    type: file\n    behavior: ipcidr\n    path: kitegeo:ip:geoip.dat:test\nrules:\n  - RULE-SET,geoip-test,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareMihomoGeoProviders(raw, assets, home); err != nil {
		t.Fatal(err)
	}
	if raw.RuleProvider["geoip-test"]["behavior"] != "classical" || strings.HasPrefix(raw.RuleProvider["geoip-test"]["path"].(string), kiteGeoPrefix) {
		t.Fatalf("provider not rewritten: %v", raw.RuleProvider["geoip-test"])
	}
}

func TestParseNetworkInterfaces(t *testing.T) {
	interfaces := parseNetworkInterfaces("wlan0|30|1500|19|192.168.1.2/24,fe80::1/64|192.168.1.1|wifi|0\nrmnet0|12|1400|17|10.0.0.2/32||cellular|1\nbad line\nwlan0|31|1500|0|||wifi|0")
	if len(interfaces) != 2 {
		t.Fatalf("interfaces = %+v", interfaces)
	}
	if interfaces[0].Name != "wlan0" || interfaces[0].Index != 30 || len(interfaces[0].Addresses) != 2 || interfaces[0].DNSServers[0] != "192.168.1.1" {
		t.Fatalf("wlan0 = %+v", interfaces[0])
	}
	if !interfaces[1].Expensive {
		t.Fatal("cellular must be expensive")
	}
}

func TestKiteCoreLifecycleWithoutStart(t *testing.T) {
	if RunningKiteCore() != "" {
		t.Fatal("nothing should run")
	}
	if err := StopKiteCore(); err != nil {
		t.Fatal(err)
	}
	if err := StartKiteCore("unknown", "", &CoreOptions{}); err == nil {
		t.Fatal("unknown core must fail")
	}
	if err := StartKiteCore(CoreMihomo, "not: [valid", &CoreOptions{Mode: ModeProxy, HomeDir: t.TempDir()}); err == nil {
		t.Fatal("invalid config must fail")
	}
	if RunningKiteCore() != "" {
		t.Fatal("failed start must leave nothing running")
	}
	if QueryKiteTrafficStats() != "" || GetKiteGroups() != "[]" {
		t.Fatal("idle core must report nothing")
	}
}

func TestKiteCoreStartStopProxyMode(t *testing.T) {
	home := t.TempDir()
	for _, core := range []string{CoreSingBox, CoreMihomo} {
		content := testSingBoxConfig
		if core == CoreMihomo {
			content = testMihomoConfig
		}
		options := &CoreOptions{Mode: ModeProxy, MixedPort: 0, HomeDir: filepath.Join(home, core), LogLevel: "warning"}
		if err := StartKiteCore(core, content, options); err != nil {
			t.Fatalf("%s: %v", core, err)
		}
		if RunningKiteCore() != core {
			t.Fatalf("running = %q", RunningKiteCore())
		}
		var groups []kiteGroup
		if err := json.Unmarshal([]byte(GetKiteGroups()), &groups); err != nil || len(groups) == 0 {
			t.Fatalf("%s groups: %v %s", core, err, GetKiteGroups())
		}
		if err := SelectKiteOutbound("proxy", "node-a"); err != nil {
			t.Fatalf("%s select: %v", core, err)
		}
		if err := StopKiteCore(); err != nil {
			t.Fatal(err)
		}
		if RunningKiteCore() != "" {
			t.Fatal("core still running after stop")
		}
	}
}
