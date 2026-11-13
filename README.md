# RHELGuard 🛡️

**RHELGuard** is a lightweight, read-only Python CLI that performs baseline security posture checks on **Red Hat Enterprise Linux 10** systems. Its goal is to make common hardening gaps visible to administrators and provide structured output that can be reviewed or consumed by automation.

> **Status:** MVP v0.1.0. This is a learning and portfolio project, not a CIS/STIG certification tool, vulnerability scanner, or substitute for professional assessment. Its simplistic score is not a compliance rating.

## Features

- SELinux runtime enforcing mode (`getenforce`)
- firewalld service state (`systemctl is-active firewalld.service`)
- SSH effective global settings (`sshd -T`): root login and password authentication
- Pending Red Hat security advisory identifiers (`dnf updateinfo list updates security`)
- auditd service state (`systemctl is-active auditd.service`)
- Explicit password minimum length (`/etc/security/pwquality.conf` and `.d/*.conf`)
- Terminal and machine-readable JSON reports
- Read-only inspection, bounded subprocess execution, no shell interpolation

## Architecture

```text
CLI -> Audit engine -> Security checks -> Findings -> Terminal / JSON
```

```text
rhelguard/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── src/rhelguard/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── engine.py
│   └── checks.py
├── tests/test_checks.py
└── docs/ROADMAP.md
```

## Requirements

- RHEL 10 (intended target) with Python 3.9 or newer
- `getenforce`, `systemctl`, `sshd`, and `dnf` where applicable
- Access to enabled security-advisory repositories for the update check
- `pytest` for running tests (development only)

No third-party Python runtime dependencies.

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/rhelguard.git
cd rhelguard
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
rhelguard audit
rhelguard audit --format json
mkdir -p reports
rhelguard audit --format json --output reports/security-report.json
```

If the system cannot install pip packages, run directly from the source checkout:

```bash
PYTHONPATH=src python3 -m rhelguard audit
```

To run tests:

```bash
python3 -m pip install pytest
python3 -m pytest -q
```

> Replace `YOUR_USERNAME` with your GitHub handle after creating a repository. You do not need to push to GitHub to run the downloaded source locally.

## Example output (illustrative)

```text
RHELGuard v0.1.0 | server1.lab.example.com
==============================================================
[PASS   ] SELinux enforcing: Runtime mode: Enforcing
[PASS   ] Firewalld active: firewalld.service: active
[PASS   ] SSH root login disabled: permitrootlogin no
[FAIL   ] SSH password auth disabled: passwordauthentication yes
[WARN   ] No pending security advisories: 2 unique RHSA advisories reported
[PASS   ] Audit daemon active: auditd.service: active
[UNKNOWN] Password minlen >= 12: No explicit minlen found; PAM enforcement and defaults not evaluated
--------------------------------------------------------------
Score (heuristic): 67%
PASS=4 FAIL=1 WARN=1 SKIP=0 UNKNOWN=1
```

## CLI

```bash
rhelguard audit
rhelguard audit --format json
rhelguard audit --format json --output report.json
rhelguard audit --fail-on fail
rhelguard audit --fail-on warn
```

`--fail-on never` (default): exit 0 after a successful scan, regardless of findings.

`--fail-on fail` / `warn`: exit 2 when matching adverse findings exist; otherwise exit 3 when unknown findings exist; otherwise exit 0. Report-writing and argument errors are nonzero.

## Finding states

| State | Meaning |
|---|---|
| PASS | Checkable baseline satisfied |
| FAIL | Baseline not satisfied |
| WARN | Needs review, or detected advisory/policy concern |
| SKIP | Explicitly non-applicable or unavailable service |
| UNKNOWN | Could not reliably determine result |

The optional **score** is a simple PASS / (PASS+FAIL+WARN) percentage. SKIP and UNKNOWN are excluded, never counted as passes. A score of 100% does **not** imply a secure host.

## Security model and limitations

1. **Read-only**: does not modify firewall, SSH, SELinux, or system services. DNF may read/refresh package metadata; it does not install packages.
2. **Least privilege**: run without root first. Some checks may be UNKNOWN because of restricted access. Avoid running third-party code as root without review.
3. **SSH**: `sshd -T` inspects effective global defaults. `Match` blocks and user-specific authentication flows can differ. Disabling password authentication should be done only after confirming reliable key-based access.
4. **Security updates**: RHSA parsing counts unique advisories, not packages. Results require appropriate repository metadata; non-RHSA advisory formats are not fully supported.
5. **Password quality**: `minlen` is a configuration inspection only, not proof that the active PAM stack enforces it; policy requirements vary.
6. **Audit results**: local checks cannot identify every misconfiguration, exploit, or security exposure.
7. **Scope**: intended for RHEL 10; results may differ on other distributions or versions.
8. **Report privacy**: reports contain hostnames and security configuration details. Store and share them carefully.

## Development

Each check accepts an injectable command runner, making tests deterministic without root or a RHEL host. Add a check by writing a function that returns `Finding`, then register it in `CHECKS`.

## Next milestones

See [docs/ROADMAP.md](docs/ROADMAP.md) for richer policy profiles, contextual SSH evaluation, password/PAM validation, HTML reporting, and GitHub Actions.

## Reference documentation

- [RHEL 10 Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/using_selinux/getting-started-with-selinux)
- [RHEL 10 Security updates](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/risk_reduction_and_recovery_operations/managing-and-monitoring-security-updates)
- [RHEL 10 Managing software updates](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_software_with_the_dnf_tool/updating-rhel-content)

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome. For new checks, include unit tests for passing, failing, and inconclusive cases. Do not include real secrets, host credentials, or private audit reports in issues.
