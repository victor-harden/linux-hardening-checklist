# 📋 Linux Hardening Checklist

Practical hardening checklist based on CIS Benchmarks + Arch Wiki recommendations,
with two verification tools: a quick shell script and a read-only Python audit that
also covers sysctl and SSH settings.

## Categories

- [ ] Disk Encryption (LUKS)
- [ ] Secure Boot
- [ ] Firewall (nftables)
- [ ] Mandatory Access Control (AppArmor)
- [ ] Kernel Hardening (sysctl)
- [ ] Service Minimization
- [ ] User Privilege Separation
- [ ] Logging & Auditing
- [ ] Automatic Updates / Notifications
- [ ] Physical Security

## Verification tools

### 1. Quick shell check

```bash
./check-hardening.sh
```

Checks that nftables, AppArmor and fail2ban are active and prints the current
value of `kernel.unprivileged_userns_clone`.

### 2. Read-only audit

```bash
python3 audit.py
python3 audit.py --json
```

Checks:

| Check | Expected |
|---|---|
| `kernel.randomize_va_space` | `2` |
| `kernel.dmesg_restrict` | `1` |
| `kernel.kptr_restrict` | `1` |
| `net.ipv4.conf.all.rp_filter` | `1` |
| `net.ipv4.tcp_syncookies` | `1` |
| `PermitRootLogin` | `no` |
| `PasswordAuthentication` | `no` |
| nftables / AppArmor | active |
| `/etc/crypttab` | at least one entry |

Statuses are `pass`, `warn`, `fail` and `skip` (unreadable value). The tool only
reads files and asks systemd for service state; it never changes anything.

Exit code is `1` when any check fails, so it can gate a provisioning pipeline.

## Tests

```bash
python3 -m unittest discover -s tests -v
bash -n check-hardening.sh
```

## Manual checklist notes

- Set sysctl values in `/etc/sysctl.d/99-hardening.conf` and apply with
  `sysctl --system`.
- Keep SSH to keys only; `PasswordAuthentication no` after confirming your key
  works.
- Prefer a default-deny firewall and open ports explicitly.
- Review `systemctl list-unit-files --state=enabled` quarterly.

## License

MIT — see [LICENSE](LICENSE).
