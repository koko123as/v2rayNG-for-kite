#!/usr/bin/env python3
"""Moves one libkite core to a new release.

    python3 tools/bump_core.py sing-box 1.14.5 [--dry-run]
    python3 tools/bump_core.py mihomo 1.19.34
    python3 tools/bump_core.py xray 26.11.1

The tag must exist and resolve through the Go proxy; its go.mod must not need
a Go newer than GO_VERSION (bump GO_VERSION alone first when it does). Xray is
moved together with the AndroidLibXrayLite submodule tag of the same version,
whose go.mod gives the xray-core module (pseudo) version. Afterwards run
tools/verify_libkite.py and the Build APK workflow.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROPS = os.path.join(ROOT, "version.properties")
LIBKITE = os.path.join(ROOT, "libkite")

MODULES = {
    "sing-box": ("github.com/sagernet/sing-box", "SING_BOX_VERSION"),
    "mihomo": ("github.com/metacubex/mihomo", "MIHOMO_VERSION"),
}


def read_props():
    with open(PROPS, encoding="utf-8") as handle:
        return handle.read()


def prop(content, key):
    match = re.search(rf"^{key}=(.*)$", content, re.M)
    return match.group(1).strip() if match else None


def set_prop(content, key, value):
    return re.sub(rf"^{key}=.*$", f"{key}={value}", content, flags=re.M)


def version_tuple(value):
    return tuple(int(x) for x in re.findall(r"\d+", value))


def proxy_info(module, version):
    url = f"https://proxy.golang.org/{module.lower()}/@v/{version}.info"
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def proxy_go_mod(module, version):
    url = f"https://proxy.golang.org/{module.lower()}/@v/{version}.mod"
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode()


def go_directive(go_mod):
    match = re.search(r"^go (\S+)", go_mod, re.M)
    return match.group(1) if match else "0"


def run(command, cwd, dry_run):
    print("$ " + " ".join(command))
    if not dry_run:
        subprocess.run(command, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("core", choices=["sing-box", "mihomo", "xray"])
    parser.add_argument("version")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    version = args.version.lstrip("v")
    content = read_props()
    go_version = prop(content, "GO_VERSION")

    if args.core == "xray":
        tag = "v" + version
        submodule = os.path.join(ROOT, "AndroidLibXrayLite")
        run(["git", "fetch", "--depth", "1", "origin", "tag", tag], submodule, args.dry_run)
        run(["git", "checkout", tag], submodule, args.dry_run)
        if args.dry_run:
            print("dry run: would read xray-core module version from AndroidLibXrayLite/go.mod")
            return 0
        with open(os.path.join(submodule, "go.mod"), encoding="utf-8") as handle:
            submodule_mod = handle.read()
        match = re.search(r"github.com/xtls/xray-core (\S+)", submodule_mod)
        if not match:
            print("xray-core not found in AndroidLibXrayLite/go.mod", file=sys.stderr)
            return 1
        module_version = match.group(1)
        needed = go_directive(proxy_go_mod("github.com/xtls/xray-core", module_version))
        if version_tuple(needed) > version_tuple(go_version):
            print(f"xray-core needs go {needed} > {go_version}; bump GO_VERSION first", file=sys.stderr)
            return 1
        run(["go", "get", f"github.com/xtls/xray-core@{module_version}"], LIBKITE, False)
        content = set_prop(content, "XRAY_VERSION", version)
        content = set_prop(content, "XRAY_MODULE_VERSION", module_version)
        content = set_prop(content, "ANDROIDLIBXRAYLITE_VERSION", tag)
    else:
        module, key = MODULES[args.core]
        tag = "v" + version
        proxy_info(module, tag)
        needed = go_directive(proxy_go_mod(module, tag))
        if version_tuple(needed) > version_tuple(go_version):
            print(f"{module} {tag} needs go {needed} > {go_version}; bump GO_VERSION first", file=sys.stderr)
            return 1
        run(["go", "get", f"{module}@{tag}"], LIBKITE, args.dry_run)
        content = set_prop(content, key, version)

    run(["bash", "libkite/build.sh", "sync"], ROOT, args.dry_run)
    run(["go", "mod", "tidy"], LIBKITE, args.dry_run)
    if args.dry_run:
        print("dry run: version.properties unchanged")
        return 0
    with open(PROPS, "w", encoding="utf-8") as handle:
        handle.write(content)
    return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "verify_libkite.py")]).returncode


if __name__ == "__main__":
    sys.exit(main())
