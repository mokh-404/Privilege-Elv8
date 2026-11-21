"""FE-08 string-sanitization assertion and DS-10 runner-footprint exclusion.

This module is an ASSERTION, not a scrubber. If any feature-input string contains a
forbidden simulation token, the build fails, the offending rows are written to
results/logs/sanitization_failures.csv, and the fix must be made at the source
(payload parameterisation or runner exclusion). Tokens are never silently removed,
because that would hide the problem and change name_length / name_entropy.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

import pandas as pd

from src import config


class SanitizationError(AssertionError):
    """Raised when a forbidden simulation token appears in a feature-input string."""

    def __init__(self, failures: pd.DataFrame, report_path: Path | None):
        self.failures = failures
        self.report_path = report_path
        n_rows = failures["artifact_key"].nunique() if len(failures) else 0
        preview = failures.head(10).to_string(index=False)
        super().__init__(
            f"FE-08 sanitization assertion failed: {len(failures)} match(es) in {n_rows} artifact row(s). "
            f"Report: {report_path}. Fix at the source (payload or runner exclusion), do not scrub.\n{preview}"
        )


def find_forbidden(
    text: object,
    patterns: Sequence = config.FORBIDDEN_PATTERNS,
    allowlist: Sequence = config.FE08_BENIGN_OS_ALLOWLIST,
) -> list[str]:
    """Return every forbidden-token match in `text` (empty list if clean or not a string)."""
    if text is None or not isinstance(text, str) or text == "":
        return []
    allowed_spans = [(am.start(), am.end()) for ap in allowlist for am in ap.finditer(text)]
    hits: list[str] = []
    for pat in patterns:
        for m in pat.finditer(text):
            if any(a0 <= m.start() and m.end() <= a1 for a0, a1 in allowed_spans):
                continue
            hits.append(m.group(0))
    return hits


def scan(df: pd.DataFrame, fields: Iterable[str] = config.STRING_INPUT_FIELDS) -> pd.DataFrame:
    """Scan all feature-input string fields. Returns one row per (artifact, field, match)."""
    records = []
    key_col = "artifact_key" if "artifact_key" in df.columns else None
    present = [f for f in fields if f in df.columns]
    for idx, row in df[present + ([key_col] if key_col else [])].iterrows():
        for field in present:
            for match in find_forbidden(row[field]):
                records.append({
                    "row_index": idx,
                    "artifact_key": row[key_col] if key_col else None,
                    "field": field,
                    "matched_text": match,
                    "value": row[field],
                })
    return pd.DataFrame(records, columns=["row_index", "artifact_key", "field", "matched_text", "value"])


def assert_clean(
    df: pd.DataFrame,
    fields: Iterable[str] = config.STRING_INPUT_FIELDS,
    report_path: str | Path | None = config.SANITIZATION_FAILURES_CSV,
) -> None:
    """Assert zero forbidden-token matches on every feature-input string.

    On failure: write the report CSV (artifact_key, field, matched text) and raise SanitizationError.
    """
    failures = scan(df, fields)
    if len(failures):
        path = None
        if report_path is not None:
            path = Path(report_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            failures.to_csv(path, index=False)
        raise SanitizationError(failures, path)


def _norm_path(p: object) -> str:
    return str(p).strip().strip('"').lower().replace("/", "\\") if isinstance(p, str) else ""


def drop_runner_footprint(
    df: pd.DataFrame,
    exclude_paths: Sequence[str] = config.RUNNER_EXCLUDE_PATHS,
    exclude_process_names: Sequence[str] = config.RUNNER_EXCLUDE_PROCESS_NAMES,
    exclude_pids: Iterable[int] = (),
    log_path: str | Path | None = config.RUNNER_FOOTPRINT_LOG_CSV,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Remove runner-footprint rows (DS-10) BEFORE sanitization; log what was dropped.

    A row is runner footprint if its path or command line starts with/contains an excluded
    path prefix, it is a process whose name is an excluded runner process (sshd.exe ...),
    or it is a process whose pid is in the per-run exclusion set (launcher wrappers,
    collector tree; read from the host-side provenance log).
    Returns (kept, dropped).
    """
    prefixes = [_norm_path(p) for p in exclude_paths if p]
    names = {n.lower() for n in exclude_process_names}
    pids = {int(p) for p in exclude_pids}

    def reason(row: pd.Series) -> str | None:
        path = _norm_path(row.get("path"))
        cmd = _norm_path(row.get("command_line"))
        for pref in prefixes:
            if path.startswith(pref) or (pref and pref in cmd):
                return f"path_prefix:{pref}"
        if row.get("artifact_type") == "process":
            nm = str(row.get("name") or "").lower()
            if nm in names:
                return f"process_name:{nm}"
            pid = row.get("pid")
            if pid is not None and not pd.isna(pid) and int(pid) in pids:
                return f"pid:{int(pid)}"
        return None

    reasons = df.apply(reason, axis=1) if len(df) else pd.Series([], dtype=object)
    mask = reasons.notna()
    dropped = df[mask].copy()
    dropped["drop_reason"] = reasons[mask]
    kept = df[~mask].copy()
    if log_path is not None and len(dropped):
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        cols = [c for c in ("run_id", "artifact_key", "artifact_type", "name", "path", "drop_reason") if c in dropped]
        dropped[cols].to_csv(path, mode="a", header=not path.exists(), index=False)
    return kept, dropped
