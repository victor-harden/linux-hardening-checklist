#!/bin/bash
# Basic hardening verification for Arch Linux

echo "=== Linux Hardening Check ==="
echo

echo "[+] Checking nftables status..."
systemctl is-active nftables && echo "  OK: nftables active" || echo "  WARN: nftables not active"

echo "[+] Checking AppArmor..."
systemctl is-active apparmor && echo "  OK: AppArmor active" || echo "  WARN: AppArmor not active"

echo "[+] Checking fail2ban..."
systemctl is-active fail2ban && echo "  OK: fail2ban active" || echo "  WARN: fail2ban not active"

echo "[+] Checking for unprivileged user namespaces..."
sysctl kernel.unprivileged_userns_clone 2>/dev/null || true

echo
echo "Check completed."
