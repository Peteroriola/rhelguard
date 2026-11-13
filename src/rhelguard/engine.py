"""Audit engine and safe command execution."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import platform
import subprocess
from typing import Callable, List, Optional


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    status: str  # PASS, FAIL, WARN, SKIP, UNKNOWN
    detail: str
    recommendation: str = ""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(*args: str, timeout: int = 15) -> Optional[CommandResult]:
    """Run a fixed argv command without a shell; None if unavailable or timed out."""
    try:
        result = subprocess.run(list(args), capture_output=True, text=True,
                                timeout=timeout, check=False)
        return CommandResult(result.returncode, result.stdout, result.stderr)
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return None


def audit(runner: Callable = run_command, etc_dir: str = "/etc") -> dict:
    from .checks import CHECKS
    findings: List[Finding] = [check(runner, etc_dir) for check in CHECKS]
    counts = {status: sum(f.status == status for f in findings)
              for status in ("PASS", "FAIL", "WARN", "SKIP", "UNKNOWN")}
    evaluated = counts["PASS"] + counts["FAIL"] + counts["WARN"]
    # Heuristic only; WARN counts as a non-pass. Unknown/skip excluded, not silently passed.
    score = round(100 * counts["PASS"] / evaluated) if evaluated else None
    return {
        "tool": "rhelguard", "version": "0.1.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node(), "platform": platform.platform(),
        "score": score, "score_note": "Simple pass ratio; not a compliance certification",
        "counts": counts, "findings": [asdict(f) for f in findings],
    }
