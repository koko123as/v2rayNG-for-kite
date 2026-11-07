package libv2ray

// Geo data shared by the three cores.
//
// The app keeps Xray's geoip.dat / geosite.dat (and extra "ext:" files such
// as geoip-only-cn-private.dat) in its asset directory.
//   - mihomo reads GeoIP.dat / GeoSite.dat from its home directory in geodata
//     mode; the files are copied there when they change (Android app storage
//     does not support symlinks). "ext:" files become generated rule
//     providers.
//   - sing-box 1.14 has no geosite/geoip database support; every rule-set the
//     app references as "kitegeo:..." is generated from the same .dat files
//     as a local binary .srs rule-set.
//
// A generated reference is written "kitegeo:<site|ip>:<file>:<code>[@attr]".

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	mihomoConfig "github.com/metacubex/mihomo/config"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

const kiteGeoPrefix = "kitegeo:"

var geoAccess sync.Mutex

type geoRef struct {
	kind string // "site" or "ip"
	file string
	code string
	attr string
}

func parseGeoRef(value string) (geoRef, bool) {
	if !strings.HasPrefix(value, kiteGeoPrefix) {
		return geoRef{}, false
	}
	parts := strings.SplitN(strings.TrimPrefix(value, kiteGeoPrefix), ":", 3)
	if len(parts) != 3 || (parts[0] != "site" && parts[0] != "ip") || parts[1] == "" || parts[2] == "" {
		return geoRef{}, false
	}
	ref := geoRef{kind: parts[0], file: filepath.Base(parts[1]), code: strings.ToLower(parts[2])}
	if index := strings.Index(ref.code, "@"); index >= 0 {
		ref.attr = ref.code[index+1:]
		ref.code = ref.code[:index]
	}
	return ref, true
}

func (r geoRef) String() string {
	value := kiteGeoPrefix + r.kind + ":" + r.file + ":" + r.code
	if r.attr != "" {
		value += "@" + r.attr
	}
	return value
}

func (r geoRef) cacheName(ext string) string {
	sum := sha1.Sum([]byte(r.String()))
	return r.kind + "-" + hex.EncodeToString(sum[:8]) + ext
}

// geoEntries reads one code of a .dat file: domain rules for "site", CIDRs for
// "ip".
type geoEntries struct {
	domain  []string
	suffix  []string
	keyword []string
	regex   []string
	cidr    []string
}

func (e *geoEntries) empty() bool {
	return len(e.domain)+len(e.suffix)+len(e.keyword)+len(e.regex)+len(e.cidr) == 0
}

func loadGeoEntries(assetDir string, ref geoRef) (*geoEntries, error) {
	content, err := os.ReadFile(filepath.Join(assetDir, ref.file))
	if err != nil {
		return nil, err
	}
	entries := &geoEntries{}
	switch ref.kind {
	case "site":
		var list geodata.GeoSiteList
		if err := proto.Unmarshal(content, &list); err != nil {
			return nil, fmt.Errorf("%s: %w", ref.file, err)
		}
		for _, site := range list.Entry {
			if !strings.EqualFold(site.Code, ref.code) {
				continue
			}
			for _, domain := range site.Domain {
				if ref.attr != "" && !hasGeoAttribute(domain, ref.attr) {
					continue
				}
				switch domain.Type {
				case geodata.Domain_Substr:
					entries.keyword = append(entries.keyword, domain.Value)
				case geodata.Domain_Regex:
					entries.regex = append(entries.regex, domain.Value)
				case geodata.Domain_Domain:
					entries.suffix = append(entries.suffix, domain.Value)
				case geodata.Domain_Full:
					entries.domain = append(entries.domain, domain.Value)
				}
			}
		}
	case "ip":
		var list geodata.GeoIPList
		if err := proto.Unmarshal(content, &list); err != nil {
			return nil, fmt.Errorf("%s: %w", ref.file, err)
		}
		for _, ip := range list.Entry {
			if !strings.EqualFold(ip.Code, ref.code) {
				continue
			}
			for _, cidr := range ip.Cidr {
				addr, ok := netip.AddrFromSlice(cidr.Ip)
				if !ok {
					continue
				}
				entries.cidr = append(entries.cidr, netip.PrefixFrom(addr.Unmap(), int(cidr.Prefix)-ipv4MappedOffset(addr)).String())
			}
		}
	}
	if entries.empty() {
		return nil, fmt.Errorf("%s: code %q not found", ref.file, ref.String())
	}
	return entries, nil
}

// A 16 byte IPv4-mapped address carries a /96 based prefix.
func ipv4MappedOffset(addr netip.Addr) int {
	if addr.Is4In6() {
		return 96
	}
	return 0
}

func hasGeoAttribute(domain *geodata.Domain, attr string) bool {
	for _, attribute := range domain.Attribute {
		if strings.EqualFold(attribute.Key, attr) {
			return true
		}
	}
	return false
}

// upToDate reports whether output exists and is not older than source.
func upToDate(output string, source string) bool {
	outInfo, err := os.Stat(output)
	if err != nil || outInfo.Size() == 0 {
		return false
	}
	srcInfo, err := os.Stat(source)
	if err != nil {
		return true
	}
	return !outInfo.ModTime().Before(srcInfo.ModTime())
}

func writeFileAtomic(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// buildSingBoxGeoRuleSet writes the binary rule-set for ref and returns its
// path.
func buildSingBoxGeoRuleSet(assetDir string, outputDir string, ref geoRef) (string, error) {
	output := filepath.Join(outputDir, ref.cacheName(".srs"))
	if upToDate(output, filepath.Join(assetDir, ref.file)) {
		return output, nil
	}
	entries, err := loadGeoEntries(assetDir, ref)
	if err != nil {
		return "", err
	}
	rule := option.DefaultHeadlessRule{}
	rule.Domain = entries.domain
	rule.DomainSuffix = entries.suffix
	rule.DomainKeyword = entries.keyword
	rule.DomainRegex = entries.regex
	rule.IPCIDR = entries.cidr
	var buffer bytes.Buffer
	err = srs.Write(&buffer, option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: rule,
	}}}, C.RuleSetVersionCurrent)
	if err != nil {
		return "", err
	}
	return output, writeFileAtomic(output, buffer.Bytes())
}

// buildMihomoGeoProvider writes a classical text rule provider for ref and
// returns its path.
func buildMihomoGeoProvider(assetDir string, outputDir string, ref geoRef) (string, error) {
	output := filepath.Join(outputDir, ref.cacheName(".txt"))
	if upToDate(output, filepath.Join(assetDir, ref.file)) {
		return output, nil
	}
	entries, err := loadGeoEntries(assetDir, ref)
	if err != nil {
		return "", err
	}
	var buffer bytes.Buffer
	for _, value := range entries.domain {
		buffer.WriteString("DOMAIN," + value + "\n")
	}
	for _, value := range entries.suffix {
		buffer.WriteString("DOMAIN-SUFFIX," + value + "\n")
	}
	for _, value := range entries.keyword {
		buffer.WriteString("DOMAIN-KEYWORD," + value + "\n")
	}
	for _, value := range entries.regex {
		buffer.WriteString("DOMAIN-REGEX," + value + "\n")
	}
	for _, value := range entries.cidr {
		if strings.Contains(value, ":") {
			buffer.WriteString("IP-CIDR6," + value + ",no-resolve\n")
		} else {
			buffer.WriteString("IP-CIDR," + value + ",no-resolve\n")
		}
	}
	return output, writeFileAtomic(output, buffer.Bytes())
}

// syncGeoForMihomo copies geoip.dat / geosite.dat into mihomo's home when
// they changed.
func syncGeoForMihomo(assetDir string, home string) {
	if assetDir == "" {
		return
	}
	geoAccess.Lock()
	defer geoAccess.Unlock()
	for source, target := range map[string]string{"geoip.dat": "GeoIP.dat", "geosite.dat": "GeoSite.dat"} {
		src := filepath.Join(assetDir, source)
		dst := filepath.Join(home, target)
		srcInfo, err := os.Stat(src)
		if err != nil {
			continue
		}
		if dstInfo, err := os.Stat(dst); err == nil && dstInfo.Size() == srcInfo.Size() && !dstInfo.ModTime().Before(srcInfo.ModTime()) {
			continue
		}
		if err := copyFile(src, dst); err != nil {
			kiteLog(LogLevelWarning, "[mihomo] copy %s: %v", source, err)
		}
	}
}

func copyFile(src string, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// prepareMihomoGeoProviders turns rule providers whose path is a kitegeo
// reference into generated local files.
func prepareMihomoGeoProviders(raw *mihomoConfig.RawConfig, assetDir string, home string) error {
	if len(raw.RuleProvider) == 0 {
		return nil
	}
	geoAccess.Lock()
	defer geoAccess.Unlock()
	for name, provider := range raw.RuleProvider {
		path, _ := provider["path"].(string)
		ref, ok := parseGeoRef(path)
		if !ok {
			continue
		}
		if assetDir == "" {
			return errors.New("missing geo asset directory")
		}
		output, err := buildMihomoGeoProvider(assetDir, filepath.Join(home, "ruleset"), ref)
		if err != nil {
			return fmt.Errorf("rule provider %s: %w", name, err)
		}
		provider["type"] = "file"
		provider["behavior"] = "classical"
		provider["format"] = "text"
		provider["path"] = output
		delete(provider, "url")
	}
	return nil
}

// prepareSingBoxGeoRuleSets replaces local rule-sets whose path is a kitegeo
// reference with generated .srs files. content is the raw JSON profile.
func prepareSingBoxGeoRuleSets(content string, assetDir string, home string) (string, error) {
	if !strings.Contains(content, kiteGeoPrefix) {
		return content, nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(content), &root); err != nil {
		return "", err
	}
	route, _ := root["route"].(map[string]any)
	if route == nil {
		return content, nil
	}
	ruleSets, _ := route["rule_set"].([]any)
	geoAccess.Lock()
	defer geoAccess.Unlock()
	for _, item := range ruleSets {
		ruleSet, _ := item.(map[string]any)
		path, _ := ruleSet["path"].(string)
		ref, ok := parseGeoRef(path)
		if !ok {
			continue
		}
		if assetDir == "" {
			return "", errors.New("missing geo asset directory")
		}
		output, err := buildSingBoxGeoRuleSet(assetDir, filepath.Join(home, "ruleset"), ref)
		if err != nil {
			return "", fmt.Errorf("rule-set %v: %w", ruleSet["tag"], err)
		}
		ruleSet["type"] = "local"
		ruleSet["format"] = "binary"
		ruleSet["path"] = output
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
