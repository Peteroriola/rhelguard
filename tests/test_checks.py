import json
from rhelguard.checks import (selinux, firewalld, ssh_root, ssh_password,
                              updates, password_length, auditd)
from rhelguard.engine import CommandResult, audit
from rhelguard.cli import main


def fake_runner(mapping):
    def run(*args, **kwargs):
        return mapping.get(tuple(args))
    return run


def test_selinux_enforcing():
    assert selinux(fake_runner({("getenforce",): CommandResult(0, "Enforcing\n", "")}), "/etc").status == "PASS"


def test_selinux_disabled():
    assert selinux(fake_runner({("getenforce",): CommandResult(0, "Disabled\n", "")}), "/etc").status == "FAIL"


def test_firewall_active():
    r = fake_runner({("systemctl", "is-active", "firewalld.service"): CommandResult(0, "active\n", "")})
    assert firewalld(r, "/etc").status == "PASS"


def test_firewall_missing_skipped():
    r = fake_runner({("systemctl", "is-active", "firewalld.service"): CommandResult(4, "unknown\n", "")})
    assert firewalld(r, "/etc").status == "SKIP"


def test_ssh_effective_config():
    r = fake_runner({("sshd", "-T"): CommandResult(0, "permitrootlogin no\npasswordauthentication yes\n", "")})
    assert ssh_root(r, "/etc").status == "PASS"
    assert ssh_password(r, "/etc").status == "FAIL"


def test_ssh_unavailable_is_unknown():
    assert ssh_root(fake_runner({}), "/etc").status == "UNKNOWN"


def test_updates_deduplicated():
    text = "RHSA-2026:1234 Important/Sec. pkg1\nRHSA-2026:1234 Important/Sec. pkg2\n"
    r = fake_runner({("dnf", "--quiet", "updateinfo", "list", "updates", "security"): CommandResult(0, text, "")})
    finding = updates(r, "/etc")
    assert finding.status == "WARN" and "1 unique" in finding.detail


def test_updates_failed_not_pass():
    r = fake_runner({("dnf", "--quiet", "updateinfo", "list", "updates", "security"): CommandResult(1, "", "repo failure")})
    assert updates(r, "/etc").status == "UNKNOWN"


def test_password_policy_dropin(tmp_path):
    security = tmp_path / "security"
    (security / "pwquality.conf.d").mkdir(parents=True)
    (security / "pwquality.conf").write_text("minlen = 9\n")
    (security / "pwquality.conf.d" / "99-local.conf").write_text("minlen = 14\n")
    assert password_length(fake_runner({}), str(tmp_path)).status == "PASS"


def test_password_policy_missing_unknown(tmp_path):
    assert password_length(fake_runner({}), str(tmp_path)).status == "UNKNOWN"


def test_audit_summary(tmp_path):
    report = audit(fake_runner({}), str(tmp_path))
    assert report["counts"]["UNKNOWN"] >= 1
    assert len(report["findings"]) == 7
    assert report["score"] is None


def test_cli_json(monkeypatch, capsys):
    monkeypatch.setattr("rhelguard.cli.audit", lambda: {"version":"0.1.0", "hostname":"test", "score":None,
        "counts":{"PASS":0,"FAIL":0,"WARN":0,"SKIP":0,"UNKNOWN":1}, "findings":[]})
    assert main(["audit", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["hostname"] == "test"


def test_cli_exit_code(monkeypatch):
    monkeypatch.setattr("rhelguard.cli.audit", lambda: {"version":"0.1.0", "hostname":"test", "score":0,
        "counts":{"PASS":0,"FAIL":1,"WARN":0,"SKIP":0,"UNKNOWN":0}, "findings":[]})
    assert main(["audit", "--fail-on", "fail"]) == 2
