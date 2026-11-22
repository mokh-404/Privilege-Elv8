"""Pytest session hygiene guard ensuring tests never mutate tracked v1 artifacts."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from src import config


_GUARDED_PATHS = (
    config.PROCESSED_DIR / "dataset_v1.parquet",
    config.SPLITS_DIR / "dataset_v1_manifest.json",
    config.RUNNER_FOOTPRINT_LOG_CSV,
    config.REPO_ROOT / "docs" / "FINAL_EVAL_PLAN.md",
)


def _sha256_or_none(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_tracked_status() -> str:
    res = subprocess.run(
        ["git", "status", "--porcelain", "--", "results/", "data/", "docs/FINAL_EVAL_PLAN.md"],
        cwd=config.REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout


@pytest.fixture(scope="session", autouse=True)
def _verify_no_tracked_mutations_during_pytest():
    before_hashes = {p: _sha256_or_none(p) for p in _GUARDED_PATHS}
    before_san_exists = config.SANITIZATION_FAILURES_CSV.exists()
    before_san_hash = _sha256_or_none(config.SANITIZATION_FAILURES_CSV)
    before_git = _git_tracked_status()
    yield
    after_hashes = {p: _sha256_or_none(p) for p in _GUARDED_PATHS}
    assert after_hashes == before_hashes, (
        f"Pytest mutated guarded tracked file(s): "
        f"{[str(p) for p in _GUARDED_PATHS if after_hashes[p] != before_hashes[p]]}"
    )
    assert config.SANITIZATION_FAILURES_CSV.exists() == before_san_exists
    assert _sha256_or_none(config.SANITIZATION_FAILURES_CSV) == before_san_hash
    after_git = _git_tracked_status()
    assert after_git == before_git, (
        f"Pytest changed git status under results/data/FINAL_EVAL_PLAN:\nBefore:\n{before_git}\nAfter:\n{after_git}"
    )
