"""Disjoint `dev` vs. `blind_test` real benign asset pool packager & auditor (Step C.6 / Task 4).

Ingests open-source Windows binaries, signed third-party utilities, scripts, and high-entropy
benign installers (`.exe`/`.msi`) into strictly disjoint host pools
(`/var/lib/dfir-quarantine-vault/benign_pools/dev` vs `.../blind_test`), asserting ZERO SHA-256,
normalized filename, and package-folder overlap.

IMPORTANT: Do NOT harvest benign assets from `win11_base.qcow2` (single Microsoft/OS vendor
violates the vendor-disjointness rule between `dev` and `blind_test` benign software pools).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Mapping, Sequence

import numpy as np

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.data.features import file_head_entropy
from src.utils.repro import utc_now_iso, write_json
from src.v2.offline_extractor import _USER_SCAN_TARGET_EXTS, verify_offline_signature


DEFAULT_POOLS_ROOT = Path("/var/lib/dfir-quarantine-vault/benign_pools")

DEV_PACKAGE_ROSTER: tuple[str, ...] = (
    "git_for_windows",
    "python312_tools",
    "curl_cli",
    "ripgrep",
    "fd_find",
    "jq_json",
    "sqlite_tools",
    "cmake_build",
    "ninja_build",
    "go_toolchain",
    "rust_cargo_tools",
    "llvm_clang_tools",
    "putty_utils",
    "winscp_portable",
    "graphviz_dot",
    "pandoc_cli",
    "ffmpeg_utils",
    "imagemagick_cli",
    "nsis_compiler",
    "sysinternals_dev",
)

BLIND_TEST_PACKAGE_ROSTER: tuple[str, ...] = (
    "notepadplusplus",
    "sevenzip_cli",
    "systeminformer",
    "vlc_portable",
    "gimp_plugins",
    "audacity_portable",
    "keepass_portable",
    "filezilla_client",
    "greenshot_util",
    "sharex_portable",
    "rufus_tool",
    "wireshark_tshark",
    "peazip_portable",
    "sumatra_pdf",
    "vscode_portable",
    "gh_cli",
    "hugo_ssg",
    "yt_dlp_oss",
    "cygwin_utils",
    "sysinternals_ops",
)

HARD_FLOOR_QUOTAS: dict[str, int] = {
    "total_files": 1000,
    "unsigned_pe": 200,
    "signed_pe": 200,
    "script": 350,
    "high_entropy_installers": 250,
    "dev_signed_pe_min": 1,
    "dev_unsigned_pe_min": 1,
    "blind_test_signed_pe_min": 1,
    "blind_test_unsigned_pe_min": 1,
}

TARGET_BENIGN_QUOTAS: dict[str, Any] = {
    "total_files_target": (1500, 2000),
    "hard_floor_files": HARD_FLOOR_QUOTAS["total_files"],
    "dev_files_target": (1200, 1600),
    "blind_test_files_target": (300, 400),
    "unsigned_pe": (300, 400),
    "signed_pe": (300, 400),
    "varied_scripts": (500, 700),
    "high_entropy_installers": (400, 500),
    "persistence_entries": (200, 400),
    "hard_floors": dict(HARD_FLOOR_QUOTAS),
}

HIGH_ENTROPY_INSTALLER_THRESHOLD = 6.5
_PE_EXTS = frozenset({".exe", ".dll"})
_INSTALLER_EXTS = frozenset({".msi"})
_SCRIPT_EXTS = frozenset({".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js"})
_AVOIDED_BENIGN_EXTS = frozenset({".hta", ".scr"})
_SAFE_PKG_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def inspect_benign_asset(path: str | Path, cat_digests: set[str] | frozenset[str] = frozenset()) -> dict[str, Any]:
    """Inspect one benign pool file strictly in user space (SHA-256, size, entropy, signature)."""
    p = Path(path)
    data = p.read_bytes()
    fsize = len(data)
    ext = p.suffix.lower()
    sha = hashlib.sha256(data).hexdigest().lower()
    ent = float(file_head_entropy(data)) if fsize > 0 else 0.0

    sig_status = verify_offline_signature(str(p), data, fsize, cat_digests=cat_digests)
    if ext in _PE_EXTS:
        category = "signed_pe" if sig_status == "Valid" else "unsigned_pe"
    elif ext in _SCRIPT_EXTS:
        category = "script"
    elif ext in _INSTALLER_EXTS:
        category = "installer_msi"
    else:
        category = "other"

    return {
        "name": p.name,
        "name_lower": p.name.lower(),
        "ext": ext,
        "sha256": sha,
        "file_size": fsize,
        "file_entropy": round(ent, 6),
        "signature_status": sig_status,
        "category": category,
        "is_collected_ext": bool(ext in _USER_SCAN_TARGET_EXTS and ext not in _AVOIDED_BENIGN_EXTS),
        "is_high_entropy_installer": bool(ext == ".msi" or (ext == ".exe" and ent >= HIGH_ENTROPY_INSTALLER_THRESHOLD)),
    }


def _collect_split_existing(split_dir: Path) -> tuple[set[str], set[str], set[str]]:
    shas: set[str] = set()
    names: set[str] = set()
    pkgs: set[str] = set()
    if not split_dir.exists():
        return shas, names, pkgs
    for pkg_dir in sorted(split_dir.iterdir()):
        if pkg_dir.is_dir():
            pkgs.add(pkg_dir.name.lower())
    for fp in sorted(split_dir.rglob("*")):
        if fp.is_file() and not fp.is_symlink():
            names.add(fp.name.lower())
            shas.add(hashlib.sha256(fp.read_bytes()).hexdigest().lower())
    return shas, names, pkgs


def ingest_package_dir(
    src_dir: str | Path,
    pools_root: str | Path,
    split_pool: str,
    package_name: str,
    allowed_exts: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Ingest real benign package files into `pools_root/<split_pool>/<package_name>/` with cross-split checks."""
    sp = str(split_pool).strip().lower()
    if sp not in ("dev", "blind_test"):
        raise ValueError(f"split_pool must be 'dev' or 'blind_test', got {split_pool!r}")
    pkg = str(package_name).strip()
    if not pkg or not _SAFE_PKG_RE.match(pkg):
        raise ValueError(f"Unsafe package_name: {package_name!r}")

    src_p = Path(src_dir)
    if not src_p.is_dir():
        raise FileNotFoundError(f"Source package directory not found: {src_p}")

    root = Path(pools_root)
    other = "blind_test" if sp == "dev" else "dev"
    other_shas, other_names, other_pkgs = _collect_split_existing(root / other)
    if pkg.lower() in other_pkgs:
        raise ValueError(f"Cross-split package collision: {pkg!r} already exists in {other}/ pool!")

    ext_filter = {e.lower() for e in allowed_exts} if allowed_exts else None
    candidates: list[tuple[Path, str]] = []
    for fp in sorted(src_p.rglob("*")):
        if not fp.is_file() or fp.is_symlink():
            continue
        if ext_filter is not None and fp.suffix.lower() not in ext_filter:
            continue
        sha = hashlib.sha256(fp.read_bytes()).hexdigest().lower()
        if sha in other_shas:
            raise ValueError(f"Cross-split SHA-256 collision on {fp.name} ({sha}) with {other}/ pool!")
        if fp.name.lower() in other_names:
            raise ValueError(f"Cross-split filename collision on {fp.name!r} with {other}/ pool!")
        candidates.append((fp, sha))

    if not candidates:
        raise ValueError(f"No eligible files found to ingest in {src_p}")

    dest_pkg_dir = root / sp / pkg
    dest_pkg_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    seen_dest_names: set[str] = set()
    for fp, sha in candidates:
        rel_safe = f"{sha[:8]}_{fp.name}" if fp.name.lower() in seen_dest_names else fp.name
        seen_dest_names.add(fp.name.lower())
        dst = dest_pkg_dir / rel_safe
        shutil.copy2(fp, dst)
        os.chmod(dst, 0o444)
        copied += 1

    return {
        "split_pool": sp,
        "package_name": pkg,
        "dest_dir": str(dest_pkg_dir),
        "files_ingested": copied,
    }


def index_and_validate_benign_pools(
    pools_root: str | Path = DEFAULT_POOLS_ROOT,
    write_manifest: bool = True,
) -> dict[str, Any]:
    """Audit `dev/` and `blind_test/` benign pools and enforce zero cross-split overlap."""
    root = Path(pools_root)
    dev_dir = root / "dev"
    test_dir = root / "blind_test"
    dev_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)

    split_records: dict[str, list[dict[str, Any]]] = {"dev": [], "blind_test": []}
    split_pkgs: dict[str, set[str]] = {"dev": set(), "blind_test": set()}
    split_shas: dict[str, set[str]] = {"dev": set(), "blind_test": set()}
    split_names: dict[str, set[str]] = {"dev": set(), "blind_test": set()}

    for sp, sdir in (("dev", dev_dir), ("blind_test", test_dir)):
        for pkg_dir in sorted(sdir.iterdir()):
            if pkg_dir.is_dir():
                split_pkgs[sp].add(pkg_dir.name.lower())
        for fp in sorted(sdir.rglob("*")):
            if not fp.is_file() or fp.is_symlink():
                continue
            rel = fp.relative_to(sdir)
            pkg = rel.parts[0] if len(rel.parts) > 1 else "unscoped"
            info = inspect_benign_asset(fp)
            info["split_pool"] = sp
            info["package_name"] = pkg
            info["rel_path"] = str(rel)
            info["abs_path"] = str(fp)
            split_records[sp].append(info)
            split_shas[sp].add(info["sha256"])
            split_names[sp].add(info["name_lower"])

    pkg_overlap = sorted(split_pkgs["dev"] & split_pkgs["blind_test"])
    sha_overlap = sorted(split_shas["dev"] & split_shas["blind_test"])
    name_overlap = sorted(split_names["dev"] & split_names["blind_test"])
    if pkg_overlap or sha_overlap or name_overlap:
        raise ValueError(
            "Cross-split benign pool overlap detected: "
            f"packages={pkg_overlap[:5]}, shas={sha_overlap[:5]}, names={name_overlap[:5]}"
        )

    def _summarize(recs: list[dict[str, Any]]) -> dict[str, Any]:
        cats = {"unsigned_pe": 0, "signed_pe": 0, "script": 0, "installer_msi": 0, "other": 0}
        ents = [float(r["file_entropy"]) for r in recs]
        sizes = [int(r["file_size"]) for r in recs]
        for r in recs:
            cats[r["category"]] = cats.get(r["category"], 0) + 1
        return {
            "total_files": len(recs),
            "unique_sha256": len({r["sha256"] for r in recs}),
            "packages_count": len({r["package_name"] for r in recs}),
            "high_entropy_installers": sum(1 for r in recs if r.get("is_high_entropy_installer")),
            "categories": cats,
            "entropy_summary": (
                {
                    "min": round(float(np.min(ents)), 4),
                    "median": round(float(np.median(ents)), 4),
                    "max": round(float(np.max(ents)), 4),
                }
                if ents
                else {}
            ),
            "size_summary": (
                {
                    "min": int(min(sizes)),
                    "median": int(np.median(sizes)),
                    "max": int(max(sizes)),
                }
                if sizes
                else {}
            ),
        }

    all_recs = split_records["dev"] + split_records["blind_test"]
    summary: dict[str, Any] = {
        "generated_at_utc": utc_now_iso(),
        "pools_root": str(root),
        "disjointness_verified": True,
        "cross_split_overlap": {"packages": 0, "sha256": 0, "filenames": 0},
        "target_quotas": TARGET_BENIGN_QUOTAS,
        "dev": _summarize(split_records["dev"]),
        "blind_test": _summarize(split_records["blind_test"]),
        "total": _summarize(all_recs),
        "assets": {
            "dev": split_records["dev"],
            "blind_test": split_records["blind_test"],
        },
    }
    summary["quota_check"] = evaluate_pool_quotas(summary)
    if write_manifest:
        write_json(summary, root / "benign_pool_manifest.json")
    return summary


def evaluate_pool_quotas(
    summary: Mapping[str, Any],
    hard_floors: Mapping[str, int] = HARD_FLOOR_QUOTAS,
) -> dict[str, Any]:
    """Validate dev/blind_test PE presence and hard floor quotas; returns pass flag + failure list."""
    failures: list[str] = []
    dev_cats = summary.get("dev", {}).get("categories", {})
    test_cats = summary.get("blind_test", {}).get("categories", {})
    tot = summary.get("total", {})
    tot_cats = tot.get("categories", {})

    if int(dev_cats.get("signed_pe", 0)) < int(hard_floors.get("dev_signed_pe_min", 1)):
        failures.append(
            f"dev signed_pe count ({dev_cats.get('signed_pe', 0)}) < required minimum ({hard_floors.get('dev_signed_pe_min', 1)})"
        )
    if int(dev_cats.get("unsigned_pe", 0)) < int(hard_floors.get("dev_unsigned_pe_min", 1)):
        failures.append(
            f"dev unsigned_pe count ({dev_cats.get('unsigned_pe', 0)}) < required minimum ({hard_floors.get('dev_unsigned_pe_min', 1)})"
        )
    if int(test_cats.get("signed_pe", 0)) < int(hard_floors.get("blind_test_signed_pe_min", 1)):
        failures.append(
            f"blind_test signed_pe count ({test_cats.get('signed_pe', 0)}) < required minimum ({hard_floors.get('blind_test_signed_pe_min', 1)})"
        )
    if int(test_cats.get("unsigned_pe", 0)) < int(hard_floors.get("blind_test_unsigned_pe_min", 1)):
        failures.append(
            f"blind_test unsigned_pe count ({test_cats.get('unsigned_pe', 0)}) < required minimum ({hard_floors.get('blind_test_unsigned_pe_min', 1)})"
        )

    tot_checks = (
        ("total_files", int(tot.get("total_files", 0)), int(hard_floors.get("total_files", 1000))),
        ("unsigned_pe", int(tot_cats.get("unsigned_pe", 0)), int(hard_floors.get("unsigned_pe", 200))),
        ("signed_pe", int(tot_cats.get("signed_pe", 0)), int(hard_floors.get("signed_pe", 200))),
        ("script", int(tot_cats.get("script", 0)), int(hard_floors.get("script", 350))),
        (
            "high_entropy_installers",
            int(tot.get("high_entropy_installers", 0)),
            int(hard_floors.get("high_entropy_installers", 250)),
        ),
    )
    for label, actual, floor in tot_checks:
        if actual < floor:
            failures.append(f"total {label} ({actual}) < hard floor ({floor})")

    return {
        "passed": len(failures) == 0,
        "failures": failures,
        "hard_floors": dict(hard_floors),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare and audit disjoint dev/blind_test benign asset pools.")
    parser.add_argument("--pools-root", type=Path, default=DEFAULT_POOLS_ROOT)
    parser.add_argument("--init-dirs", action="store_true", help="Create dev/ and blind_test/ package directories")
    parser.add_argument("--ingest-dir", type=Path, default=None, help="Directory of real benign files to ingest")
    parser.add_argument("--split", choices=("dev", "blind_test"), default="dev")
    parser.add_argument("--package", default=None, help="Package directory name for --ingest-dir")
    parser.add_argument("--audit", action="store_true", help="Audit pools and write benign_pool_manifest.json")
    parser.add_argument(
        "--enforce-quotas",
        action="store_true",
        help="Exit non-zero if dev or blind_test lacks signed/unsigned PEs or misses hard floors",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    out: dict[str, Any] = {}
    if args.init_dirs:
        for pkg in DEV_PACKAGE_ROSTER:
            (args.pools_root / "dev" / pkg).mkdir(parents=True, exist_ok=True)
        for pkg in BLIND_TEST_PACKAGE_ROSTER:
            (args.pools_root / "blind_test" / pkg).mkdir(parents=True, exist_ok=True)
        out["initialized_dev_dirs"] = len(DEV_PACKAGE_ROSTER)
        out["initialized_blind_test_dirs"] = len(BLIND_TEST_PACKAGE_ROSTER)

    if args.ingest_dir is not None:
        if not args.package:
            parser.error("--ingest-dir requires --package")
        out["ingested"] = ingest_package_dir(
            src_dir=args.ingest_dir,
            pools_root=args.pools_root,
            split_pool=args.split,
            package_name=args.package,
        )

    quota_failed = False
    if args.audit or args.enforce_quotas or (not args.init_dirs and args.ingest_dir is None):
        rep = index_and_validate_benign_pools(args.pools_root, write_manifest=True)
        out["audit"] = {k: v for k, v in rep.items() if k != "assets"}
        if args.enforce_quotas and not rep["quota_check"]["passed"]:
            quota_failed = True

    print(json.dumps(out, indent=2))
    if quota_failed:
        for msg in out["audit"]["quota_check"]["failures"]:
            print(f"QUOTA ERROR: {msg}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
