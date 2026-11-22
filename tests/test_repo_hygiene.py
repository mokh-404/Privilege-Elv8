"""Repository & v1 freeze hygiene tests (IMP-15)."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pandas as pd

from src import config
from src.data import labeler


FROZEN_DATASET_V1_SHA256 = "39527f85fbda75f952e0cf5134a07467bf546501cb540ba68cd65b14983c7f21"
FROZEN_MANIFEST_V1_SHA256 = "788b6a7cab836c1851a90c5069e89496aa748c33f86643a84d9d70cc50857fbe"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def test_frozen_v1_artifacts_hashes_and_log_lines():
    parquet_path = config.PROCESSED_DIR / "dataset_v1.parquet"
    manifest_path = config.SPLITS_DIR / "dataset_v1_manifest.json"
    assert _sha256(parquet_path) == FROZEN_DATASET_V1_SHA256
    assert _sha256(manifest_path) == FROZEN_MANIFEST_V1_SHA256
    lines = config.RUNNER_FOOTPRINT_LOG_CSV.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 99


def test_labeler_with_tmp_paths_does_not_touch_tracked_logs(tmp_path):
    before_log = config.RUNNER_FOOTPRINT_LOG_CSV.read_bytes()
    before_san_exists = config.SANITIZATION_FAILURES_CSV.exists()

    df = pd.DataFrame([
        {
            "artifact_type": "process",
            "artifact_key": "process|c:\\programdata\\ssh\\sshd.exe|sshd.exe",
            "name": "sshd.exe",
            "path": "C:\\ProgramData\\ssh\\sshd.exe",
            "pid": 123,
        },
        {
            "artifact_type": "file",
            "artifact_key": "file|c:\\users\\public\\notes.txt|notes.txt",
            "name": "notes.txt",
            "path": "C:\\Users\\Public\\notes.txt",
        },
    ])
    tmp_log = tmp_path / "runner_dropped.csv"
    out = labeler.label_run(
        df,
        baseline_index={},
        provenance_rows=[],
        run_id="r_hygiene",
        runner_log_path=tmp_log,
        sanitization_report=tmp_path / "san.csv",
    )
    assert len(out) == 1
    assert tmp_log.exists()
    assert config.RUNNER_FOOTPRINT_LOG_CSV.read_bytes() == before_log
    assert config.SANITIZATION_FAILURES_CSV.exists() == before_san_exists


def test_git_diff_v1_frozen_dirs_clean():
    res = subprocess.run(
        ["git", "diff", "--stat", "--", "results/", "data/", "docs/FINAL_EVAL_PLAN.md"],
        cwd=config.REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == ""
