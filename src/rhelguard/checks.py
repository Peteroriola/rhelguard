"""Individual read-only security checks for RHEL-like hosts."""
from pathlib import Path
import re
from .engine import Finding


def _f(identifier, title, status, detail, recommendation=""):
    return Finding(identifier, title, status, detail, recommendation)


def _config_value(path, key):
    """Last active KEY=value setting in a simple config file."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    matches = re.findall(r"^\s*" + re.escape(key) + r"\s*=\s*([^#\n]+)", text, re.M | re.I)
    return matches[-1].strip() if matches else None


def selinux(runner, etc_dir):
    r = runner("getenforce")
    if r is None or r.returncode != 0:
        return _f("SELINUX", "SELinux enforcing", "UNKNOWN", "Unable to read SELinux mode")
    mode = r.stdout.strip().lower()
    if mode == "enforcing":
        return _f("SELINUX", "SELinux enforcing", "PASS", "Runtime mode: Enforcing")
    if mode in ("permissive", "disabled"):
        return _f("SELINUX", "SELinux enforcing", "FAIL", "Runtime mode: " + mode,
                  "Review SELinux policy and configure enforcing mode safely")
    return _f("SELINUX", "SELinux enforcing", "UNKNOWN", "Unexpected mode: " + mode)


def service(runner, unit, identifier, title):
    r = runner("systemctl", "is-active", unit)
    if r is None:
        return _f(identifier, title, "UNKNOWN", "systemctl unavailable")
    state = r.stdout.strip()
    if r.returncode == 0 and state == "active":
        return _f(identifier, title, "PASS", f"{unit}: active")
    if state in ("inactive", "failed", "activating", "deactivating"):
        return _f(identifier, title, "FAIL", f"{unit}: {state}",
                  f"Investigate: systemctl status {unit}")
    if state == "unknown" or "not-found" in r.stderr.lower() or "could not be found" in r.stderr.lower():
        return _f(identifier, title, "SKIP", f"{unit} not installed or not found")
    return _f(identifier, title, "UNKNOWN", f"Unable to confirm {unit} state: {state or r.stderr.strip()}")


def firewalld(runner, etc_dir):
    return service(runner, "firewalld.service", "FIREWALL", "Firewalld active")


def auditd(runner, etc_dir):
    return service(runner, "auditd.service", "AUDITD", "Audit daemon active")


def _sshd_settings(runner):
    # sshd -T reports effective global settings (including drop-ins); Match blocks
    # can override these for particular users/addresses.
    r = runner("sshd", "-T")
    if r is None:
        r = runner("/usr/sbin/sshd", "-T")
    if r is None:
        return None, "sshd binary unavailable"
    if r.returncode != 0:
        return None, (r.stderr.strip() or "sshd -T failed")
    settings = {}
    for line in r.stdout.splitlines():
        parts = line.lower().split(None, 1)
        if len(parts) == 2:
            settings[parts[0]] = parts[1].strip()
    return settings, ""


def ssh_root(runner, etc_dir):
    settings, error = _sshd_settings(runner)
    if settings is None:
        return _f("SSH_ROOT", "SSH root login disabled", "UNKNOWN", error)
    value = settings.get("permitrootlogin")
    if value is None:
        return _f("SSH_ROOT", "SSH root login disabled", "UNKNOWN", "Setting missing from sshd -T")
    if value == "no":
        return _f("SSH_ROOT", "SSH root login disabled", "PASS", "permitrootlogin no")
    return _f("SSH_ROOT", "SSH root login disabled", "FAIL", f"permitrootlogin {value}",
              "Consider PermitRootLogin no after validating alternate administrative access")


def ssh_password(runner, etc_dir):
    settings, error = _sshd_settings(runner)
    if settings is None:
        return _f("SSH_PASSWORD", "SSH password auth disabled", "UNKNOWN", error)
    value = settings.get("passwordauthentication")
    if value is None:
        return _f("SSH_PASSWORD", "SSH password auth disabled", "UNKNOWN", "Setting missing from sshd -T")
    if value == "no":
        return _f("SSH_PASSWORD", "SSH password auth disabled", "PASS", "passwordauthentication no")
    return _f("SSH_PASSWORD", "SSH password auth disabled", "FAIL", f"passwordauthentication {value}",
              "Configure key-based access and test it before disabling password authentication")


def updates(runner, etc_dir):
    r = runner("dnf", "--quiet", "updateinfo", "list", "updates", "security", timeout=90)
    if r is None or r.returncode != 0:
        reason = "DNF unavailable or timed out" if r is None else (r.stderr.strip() or f"DNF exited {r.returncode}")
        return _f("UPDATES", "No pending security advisories", "UNKNOWN", reason)
    # One advisory can affect multiple packages; deduplicate RHSA IDs.
    ids = set(re.findall(r"\bRHSA-\d{4}:\d+\b", r.stdout))
    if ids:
        return _f("UPDATES", "No pending security advisories", "WARN",
                  f"{len(ids)} unique RHSA advisories reported",
                  "Review advisories and schedule security updates")
    if r.stdout.strip():
        # Unexpected non-empty output may indicate another advisory format.
        return _f("UPDATES", "No pending security advisories", "UNKNOWN",
                  "Unrecognized DNF output; inspect manually")
    return _f("UPDATES", "No pending security advisories", "PASS", "No pending RHSA entries reported by DNF")


def password_length(runner, etc_dir):
    path = Path(etc_dir) / "security" / "pwquality.conf"
    value = _config_value(path, "minlen")
    dropins = sorted((Path(etc_dir) / "security" / "pwquality.conf.d").glob("*.conf"))
    for item in dropins:
        override = _config_value(item, "minlen")
        if override is not None:
            value = override
    if value is None:
        return _f("PWQUALITY", "Password minlen >= 12", "UNKNOWN",
                  "No explicit minlen found; PAM enforcement and defaults not evaluated")
    try:
        minimum = int(value)
    except ValueError:
        return _f("PWQUALITY", "Password minlen >= 12", "UNKNOWN", f"Invalid minlen: {value}")
    if minimum >= 12:
        return _f("PWQUALITY", "Password minlen >= 12", "PASS",
                  f"Configured minlen: {minimum} (PAM enforcement not verified)")
    return _f("PWQUALITY", "Password minlen >= 12", "WARN", f"Configured minlen: {minimum}",
              "Review password quality policy and PAM configuration")


CHECKS = [selinux, firewalld, ssh_root, ssh_password, updates, auditd, password_length]
