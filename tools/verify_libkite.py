#!/usr/bin/env python3
"""Checks that libkite builds exactly the pinned cores.

- libkite/go.mod requires the Xray, mihomo, sing-box and x/mobile versions of
  version.properties, and its go directive is not newer than GO_VERSION.
- The AndroidLibXrayLite submodule (source of the libv2ray API) pins the same
  xray-core module version.
- github.com/sagernet/sing is the version sing-box itself requires: Xray and
  mihomo must not move it.
- Writes libkite/build/core-module-bumps.txt: shared modules whose version
  differs from what the sing-box release requires.

Exit status 1 on any mismatch.
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def props():
    values = {}
    with open(os.path.join(ROOT, "version.properties"), encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    return values


def parse_go_mod(path):
    requires = {}
    go_version = None
    in_block = False
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("//")[0].strip()
            if not line:
                continue
            if line.startswith("go "):
                go_version = line.split()[1]
            elif line.startswith("require ("):
                in_block = True
            elif in_block and line == ")":
                in_block = False
            elif in_block:
                parts = line.split()
                if len(parts) >= 2:
                    requires[parts[0]] = parts[1]
            elif line.startswith("require "):
                parts = line.split()
                if len(parts) >= 3:
                    requires[parts[1]] = parts[2]
    return go_version, requires


def version_tuple(value):
    return tuple(int(x) for x in re.findall(r"\d+", value))


def module_go_mod(module, version):
    output = subprocess.run(
        ["go", "mod", "download", "-json", f"{module}@{version}"],
        cwd=os.path.join(ROOT, "libkite"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(output)["GoMod"]


def main():
    errors = []
    pins = props()
    go_version, requires = parse_go_mod(os.path.join(ROOT, "libkite", "go.mod"))

    expected = {
        "github.com/xtls/xray-core": pins["XRAY_MODULE_VERSION"],
        "github.com/metacubex/mihomo": "v" + pins["MIHOMO_VERSION"],
        "github.com/sagernet/sing-box": "v" + pins["SING_BOX_VERSION"],
        "golang.org/x/mobile": pins["GOMOBILE_VERSION"],
    }
    for module, version in expected.items():
        actual = requires.get(module)
        if actual != version:
            errors.append(f"libkite/go.mod: {module} is {actual}, version.properties pins {version}")

    if go_version and version_tuple(go_version) > version_tuple(pins["GO_VERSION"]):
        errors.append(f"libkite/go.mod needs go {go_version}, newer than GO_VERSION {pins['GO_VERSION']}")

    submodule_mod = os.path.join(ROOT, "AndroidLibXrayLite", "go.mod")
    if os.path.exists(submodule_mod):
        _, submodule_requires = parse_go_mod(submodule_mod)
        submodule_xray = submodule_requires.get("github.com/xtls/xray-core")
        if submodule_xray != pins["XRAY_MODULE_VERSION"]:
            errors.append(
                f"AndroidLibXrayLite pins xray-core {submodule_xray}, version.properties pins {pins['XRAY_MODULE_VERSION']}"
            )
        try:
            tag = subprocess.run(
                ["git", "describe", "--tags", "--exact-match"],
                cwd=os.path.join(ROOT, "AndroidLibXrayLite"),
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if tag != pins["ANDROIDLIBXRAYLITE_VERSION"]:
                errors.append(f"AndroidLibXrayLite is at {tag}, version.properties pins {pins['ANDROIDLIBXRAYLITE_VERSION']}")
        except subprocess.CalledProcessError:
            print("note: AndroidLibXrayLite tag not available (shallow checkout?), skipped tag check")
    else:
        errors.append("AndroidLibXrayLite submodule is not checked out")

    singbox_mod = module_go_mod("github.com/sagernet/sing-box", "v" + pins["SING_BOX_VERSION"])
    singbox_go, singbox_requires = parse_go_mod(singbox_mod)
    sing_expected = singbox_requires.get("github.com/sagernet/sing")
    sing_actual = requires.get("github.com/sagernet/sing")
    if sing_expected != sing_actual:
        errors.append(f"github.com/sagernet/sing moved from {sing_expected} (sing-box) to {sing_actual}")

    bumps = []
    for module, version in sorted(requires.items()):
        base = singbox_requires.get(module)
        if base and base != version:
            bumps.append(f"{module} {base} -> {version}")
    added = sorted(set(requires) - set(singbox_requires))
    report_dir = os.path.join(ROOT, "libkite", "build")
    os.makedirs(report_dir, exist_ok=True)
    with open(os.path.join(report_dir, "core-module-bumps.txt"), "w", encoding="utf-8") as handle:
        handle.write(f"sing-box v{pins['SING_BOX_VERSION']} (go {singbox_go}) baseline\n")
        handle.write(f"changed versions ({len(bumps)}):\n")
        for line in bumps:
            handle.write(f"  {line}\n")
        handle.write(f"modules added by Xray/mihomo/libv2ray ({len(added)}):\n")
        for module in added:
            handle.write(f"  {module} {requires[module]}\n")
    print(f"core-module-bumps: {len(bumps)} changed, {len(added)} added; github.com/sagernet/sing {sing_actual}")

    if errors:
        for error in errors:
            print("error: " + error, file=sys.stderr)
        return 1
    print("libkite pins verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
