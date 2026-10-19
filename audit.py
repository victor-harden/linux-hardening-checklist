#!/usr/bin/env python3
"""Read-only Linux hardening audit.

Checks a small set of high-value settings and prints a report. It never changes
the system: every check reads a file or asks systemd for a service state.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

SYSCTL_EXPECTED = {
    "kernel.randomize_va_space": "2",
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.tcp_syncookies": "1",
}

SSH_EXPECTED = {
    "permitrootlogin": "no",
    "passwordauthentication": "no",
}

SERVICES = ["nftables", "apparmor"]


def parse_sysctl(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def parse_sshd_config(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        values[parts[0].lower()] = parts[1].split()[0].lower()
    return values


def parse_crypttab(text: str) -> list:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line.split()[0])
    return entries


def service_active(name: str) -> tuple[bool, str]:
    if shutil.which("systemctl") is None:
        return False, "systemctl not available"
    proc = subprocess.run(["systemctl", "is-active", name],
                          capture_output=True, text=True, timeout=5)
    state = proc.stdout.strip() or "unknown"
    return proc.returncode == 0 and state == "active", state


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def audit(proc_sys: Path = Path("/proc/sys"), ssh_config: Path = Path("/etc/ssh/sshd_config"),
          crypttab: Path = Path("/etc/crypttab")):
    results = []

    for key, expected in SYSCTL_EXPECTED.items():
        path = proc_sys / key.replace(".", "/")
        actual = read(path).strip()
        if not actual:
            results.append({"id": f"sysctl:{key}", "status": "skip",
                            "detail": "value not readable"})
        elif actual == expected:
            results.append({"id": f"sysctl:{key}", "status": "pass",
                            "detail": f"{key}={actual}"})
        else:
            results.append({"id": f"sysctl:{key}", "status": "fail",
                            "detail": f"{key}={actual} (expected {expected})"})

    ssh_text = read(ssh_config)
    ssh = parse_sshd_config(ssh_text)
    for key, expected in SSH_EXPECTED.items():
        if key not in ssh:
            results.append({"id": f"ssh:{key}", "status": "warn",
                            "detail": f"{key} not set explicitly"})
        elif ssh[key] == expected:
            results.append({"id": f"ssh:{key}", "status": "pass",
                            "detail": f"{key} {ssh[key]}"})
        else:
            results.append({"id": f"ssh:{key}", "status": "fail",
                            "detail": f"{key} {ssh[key]} (expected {expected})"})

    for service in SERVICES:
        ok, detail = service_active(service)
        results.append({"id": f"service:{service}", "status": "pass" if ok else "warn",
                        "detail": detail})

    encrypted = parse_crypttab(read(crypttab))
    results.append({
        "id": "disk:encryption",
        "status": "pass" if encrypted else "warn",
        "detail": f"crypttab entries: {', '.join(encrypted) or 'none'}",
    })
    return results


def summarize(results) -> dict:
    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    return counts


def render(results) -> str:
    lines = []
    for result in results:
        lines.append(f"[{result['status'].upper():<4}] {result['id']:<34} {result['detail']}")
    counts = summarize(results)
    lines.append("")
    lines.append("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Linux hardening audit (read-only)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    results = audit()
    if args.json:
        print(json.dumps({"results": results, "summary": summarize(results)}, indent=2))
    else:
        print(render(results))
    return 0 if not any(r["status"] == "fail" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
