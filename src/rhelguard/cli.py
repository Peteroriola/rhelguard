"""Command-line interface."""
import argparse
import json
import sys
from pathlib import Path
from .engine import audit


def main(argv=None):
    parser = argparse.ArgumentParser(prog="rhelguard", description="Read-only RHEL security auditor")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("audit", help="Audit the local machine")
    check.add_argument("--format", choices=("terminal", "json"), default="terminal")
    check.add_argument("--output", type=Path, help="Write report to file instead of stdout")
    check.add_argument("--fail-on", choices=("never", "fail", "warn"), default="never",
                       help="Exit nonzero for configured findings (UNKNOWN alone returns 3)")
    args = parser.parse_args(argv)
    report = audit()
    if args.format == "json":
        output = json.dumps(report, indent=2) + "\n"
    else:
        rows = [f"RHELGuard v{report['version']} | {report['hostname']}",
                "=" * 62]
        for finding in report["findings"]:
            rows.append(f"[{finding['status']:<7}] {finding['title']}: {finding['detail']}")
            if finding["recommendation"]:
                rows.append(f"          Next: {finding['recommendation']}")
        rows.append("-" * 62)
        rows.append(f"Score (heuristic): {report['score'] if report['score'] is not None else 'N/A'}"
                    + ("%" if report['score'] is not None else ""))
        rows.append("PASS={PASS} FAIL={FAIL} WARN={WARN} SKIP={SKIP} UNKNOWN={UNKNOWN}".format(**report["counts"]))
        output = "\n".join(rows) + "\n"
    if args.output:
        try:
            args.output.write_text(output, encoding="utf-8")
        except OSError as exc:
            parser.error(f"could not write report: {exc}")
    else:
        sys.stdout.write(output)
    counts = report["counts"]
    if args.fail_on != "never":
        if counts["FAIL"] or (args.fail_on == "warn" and counts["WARN"]):
            return 2
        if counts["UNKNOWN"]:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
