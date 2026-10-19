import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import audit


class ParserTests(unittest.TestCase):
    def test_parse_sysctl(self):
        text = "kernel.randomize_va_space = 2\n# comment\nnet.ipv4.tcp_syncookies=1\n"
        values = audit.parse_sysctl(text)
        self.assertEqual(values["kernel.randomize_va_space"], "2")
        self.assertEqual(values["net.ipv4.tcp_syncookies"], "1")

    def test_parse_sshd_config(self):
        text = "# comment\nPermitRootLogin no\nPasswordAuthentication  no\nPort 22\n"
        values = audit.parse_sshd_config(text)
        self.assertEqual(values["permitrootlogin"], "no")
        self.assertEqual(values["passwordauthentication"], "no")
        self.assertEqual(values["port"], "22")

    def test_parse_sshd_ignores_malformed(self):
        values = audit.parse_sshd_config("JustOneToken\nPermitRootLogin yes\n")
        self.assertEqual(values, {"permitrootlogin": "yes"})

    def test_parse_crypttab(self):
        text = "# comment\ncryptroot UUID=abc none luks\ncrypthome /dev/sda2 none luks\n"
        self.assertEqual(audit.parse_crypttab(text), ["cryptroot", "crypthome"])

    def test_parse_crypttab_empty(self):
        self.assertEqual(audit.parse_crypttab("# only comments\n"), [])


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.proc_sys = base / "sys"
        (self.proc_sys / "kernel" / "net" / "ipv4" / "conf" / "all").mkdir(parents=True)
        for key, value in audit.SYSCTL_EXPECTED.items():
            path = self.proc_sys / key.replace(".", "/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value + "\n")
        self.ssh = base / "sshd_config"
        self.ssh.write_text("PermitRootLogin no\nPasswordAuthentication no\n")
        self.crypttab = base / "crypttab"
        self.crypttab.write_text("cryptroot UUID=abc none luks\n")

    def tearDown(self):
        self.tmp.cleanup()

    def by_id(self, results):
        return {result["id"]: result for result in results}

    def test_hardened_configuration_passes(self):
        results = audit.audit(self.proc_sys, self.ssh, self.crypttab)
        by_id = self.by_id(results)
        self.assertEqual(by_id["sysctl:kernel.randomize_va_space"]["status"], "pass")
        self.assertEqual(by_id["ssh:permitrootlogin"]["status"], "pass")
        self.assertEqual(by_id["disk:encryption"]["status"], "pass")

    def test_weak_sysctl_fails(self):
        path = self.proc_sys / "kernel" / "randomize_va_space"
        path.write_text("0\n")
        results = audit.audit(self.proc_sys, self.ssh, self.crypttab)
        self.assertEqual(self.by_id(results)["sysctl:kernel.randomize_va_space"]["status"], "fail")

    def test_root_login_enabled_fails(self):
        self.ssh.write_text("PermitRootLogin yes\n")
        results = audit.audit(self.proc_sys, self.ssh, self.crypttab)
        self.assertEqual(self.by_id(results)["ssh:permitrootlogin"]["status"], "fail")

    def test_unset_ssh_setting_warns(self):
        self.ssh.write_text("Port 22\n")
        results = audit.audit(self.proc_sys, self.ssh, self.crypttab)
        self.assertEqual(self.by_id(results)["ssh:passwordauthentication"]["status"], "warn")

    def test_missing_sysctl_is_skip(self):
        (self.proc_sys / "kernel" / "dmesg_restrict").unlink()
        results = audit.audit(self.proc_sys, self.ssh, self.crypttab)
        self.assertEqual(self.by_id(results)["sysctl:kernel.dmesg_restrict"]["status"], "skip")

    def test_summary_counts(self):
        results = audit.audit(self.proc_sys, self.ssh, self.crypttab)
        counts = audit.summarize(results)
        self.assertEqual(sum(counts.values()), len(results))
        self.assertIn("pass", counts)

    def test_render_contains_ids(self):
        text = audit.render(audit.audit(self.proc_sys, self.ssh, self.crypttab))
        self.assertIn("sysctl:kernel.randomize_va_space", text)
        self.assertIn("summary:", text)


if __name__ == "__main__":
    unittest.main()
