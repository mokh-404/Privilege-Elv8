"""Reproducibility helpers: seeding, device selection, commit hash, run metadata."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from src import config


def set_global_seed(seed: int = config.SEED) -> None:
    """Seed python, numpy and torch (if installed). Enables deterministic torch kernels."""
    random.seed(seed)
    np.random.seed(seed)
    os.environ.setdefault("PYTHONHASHSEED", str(seed))
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    except ImportError:  # pragma: no cover
        pass


def get_device(prefer_cuda: bool = True) -> str:
    """Return "cuda" if a usable CUDA device exists, else "cpu" (clean CPU fallback)."""
    if os.environ.get("DFIR_FORCE_CPU") == "1":
        return "cpu"
    try:
        import torch

        if prefer_cuda and torch.cuda.is_available():
            try:
                torch.zeros(1, device="cuda")
                return "cuda"
            except Exception:  # driver present but unusable
                return "cpu"
    except ImportError:  # pragma: no cover
        pass
    return "cpu"


def get_commit_hash(short: bool = False) -> str:
    """Current git commit hash, with "-dirty" suffix if the tree has uncommitted changes."""
    try:
        args = ["git", "rev-parse", "--short" if short else "HEAD"]
        if short:
            args.append("HEAD")
        h = subprocess.check_output(args, cwd=config.REPO_ROOT, stderr=subprocess.DEVNULL).decode().strip()
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=config.REPO_ROOT,
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        return h + ("-dirty" if dirty else "")
    except Exception:
        return "unknown"


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_metadata(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Metadata recorded in every results file: commit, seeds, versions, device, time."""
    meta: dict[str, Any] = {
        "commit": get_commit_hash(),
        "generated_at_utc": utc_now_iso(),
        "seed": config.SEED,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "device": get_device(),
    }
    for mod in ("numpy", "pandas", "sklearn", "xgboost", "torch", "shap"):
        try:
            meta[f"{mod}_version"] = __import__(mod).__version__
        except Exception:
            meta[f"{mod}_version"] = None
    if extra:
        meta.update(extra)
    return meta


def write_json(obj: Any, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True, default=str)
    return path
