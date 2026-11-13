# Roadmap

## v0.1 — Baseline MVP
- [x] Seven read-only checks
- [x] Terminal and JSON reports
- [x] Deterministic unit tests
- [x] Installable Python CLI

## v0.2 — Reliability and policy awareness
- [ ] Interpret `sshd -T -C` for user/host/address contexts and account for `Match` blocks
- [ ] Correctly distinguish intentionally uninstalled services from unavailable commands
- [ ] Evaluate PAM active stack and effective pwquality configuration rather than only minlen files
- [ ] Support non-RHSA advisories and package-level summaries
- [ ] Add SELinux persisted-configuration/boot-setting checks
- [ ] Add structured severity, remediation documentation, and configurable policy thresholds

## v0.3 — Operational reporting
- [ ] HTML and SARIF output
- [ ] Policy profiles for workstation/server scenarios
- [ ] GitHub Actions test matrix and static analysis
- [ ] Signed builds and release archives

## v1.0 — Controlled enterprise use
- [ ] Remote execution through Ansible, no password handling in the CLI
- [ ] Versioned rule catalog and documented false-positive paths
- [ ] Tested against fresh RHEL 10 VMs and hardening variants
- [ ] Optional opt-in remediation playbooks with safeguards and rollbacks
