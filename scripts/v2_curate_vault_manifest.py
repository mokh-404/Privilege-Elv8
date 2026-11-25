"""Gate-0-guarded MalwareBazaar curation & paired Stage A/B batch builder (`OD-V2-05`, `OD-V2-07`, `OD-V2-08`).

Safety invariants:
1. Refuses execution unless `<vault_root>/GATE0_SIGNED_OFF` passes `05_quarantine_vault_setup.sh preflight`
   (`0400` permissions, all required non-empty fields, SHA-256 manifest match).
2. Hard-excludes ransomware, wipers, and self-propagating worms via `FORBIDDEN_MALWARE_FAMILIES_AND_TAGS`.
3. Standalone Runnable `.exe` PE Gate: validates every candidate in RAM with `pefile` (`pe.is_exe()`,
   `not pe.is_dll()`, `not pe.is_driver()`, x86/x64) before writing encrypted `0400` archives to the vault.
4. Reads `ABUSECH_AUTH_KEY` exclusively from `os.environ` (never hardcoded, never written to disk or stdout).
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping, Protocol, Sequence
import urllib.parse
import urllib.request

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.utils.repro import utc_now_iso, write_json
from src.v2.pilot_staging import (
    ALLOWED_FAMILIES,
    CANONICAL_ALLOWED_FAMILIES,
    FORBIDDEN_MALWARE_FAMILIES_AND_TAGS,
    PilotStagingError,
    StageRunSpec,
    assert_allowed_malware_policy,
    canonicalize_family_name,
    check_forbidden_malware_policy,
    normalize_family_slug,
    read_vault_payload_in_memory,
    validate_stage_run_spec,
)

MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
DEFAULT_VAULT_ROOT = Path.home() / ".quarantine_vault_dfir_v2"
DEFAULT_SETUP_SCRIPT = _REPO_ROOT / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"

# Priority non-destructive Windows PE categories & family tags (ZERO ransomware, wipers, or worms;
# njrat/bladabindi/qakbot/emotet/trickbot excluded pending supervisor decision).
CATEGORY_SEARCH_TAGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("stealer", (
        "RedLine", "LummaC2", "Lumma", "AgentTesla", "Vidar", "Raccoon", "Formbook", "XLoader",
        "SnakeKeylogger", "Lokibot", "MetaStealer", "RisePro", "Stealc", "Rhadamanthys",
        "Aurora", "PhoenixKeylogger", "MassLogger",
    )),
    ("rat", (
        "AsyncRAT", "RemcosRAT", "QuasarRAT", "DcRAT", "VenomRAT", "NanoCore",
        "DarkComet", "OrcusRAT", "BitRAT", "WarzoneRAT", "AveMaria", "PhantomRAT", "PoisonIvy",
    )),
    ("loader", (
        "SmokeLoader", "Amadey", "PrivateLoader", "GuLoader", "Bumblebee", "SystemBC",
        "PureCrypter", "HijackLoader", "Latrodectus", "DBatLoader", "ModiLoader", "BazarLoader",
    )),
    ("miner_clipper", (
        "XMRig", "xmrig", "SilentCryptoMiner", "ClipBanker", "LaplasClipper", "coinminer",
    )),
    ("trojan_installer", (
        "CobaltStrike", "NetWire", "Pony", "IcedID",
        "BuerLoader", "ZLoader", "exe", "persistence",
    )),
)

_WINDOWS_PE_EXTS = (".exe",)
_DISALLOWED_NON_EXE_EXTS = (
    ".dll", ".cpl", ".sys", ".ocx", ".scr", ".msi", ".elf", ".apk", ".macho",
    ".pdf", ".doc", ".zip", ".rar", ".iso", ".lnk", ".ps1", ".vbs", ".js", ".bat", ".hta",
)
_PERSISTENCE_HINT_TOKENS = (
    "persist",
    "startup",
    "run",
    "scheduled",
    "service",
    "miner",
    "xmrig",
    "amadey",
    "remcos",
    "asyncrat",
    "quasar",
    "redline",
    "lumma",
    "agenttesla",
    "smokeloader",
    "guloader",
    "clipbanker",
)
_VALID_X86_MACHINES = {0x014C, 0x8664}


class SampleFeedClient(Protocol):
    """Protocol for MalwareBazaar-compatible metadata & sample archive fetching."""

    def query_tag(self, tag: str, limit: int = 50) -> list[dict[str, Any]]: ...

    def download_sample_zip(self, sha256_hash: str) -> bytes: ...


class MalwareBazaarClient:
    """HTTP client for MalwareBazaar v1 API using runtime `Auth-Key` from environment."""

    def __init__(self, api_key: str, base_url: str = MALWAREBAZAAR_API_URL, timeout: float = 30.0):
        if not str(api_key or "").strip():
            raise RuntimeError("ABUSECH_AUTH_KEY environment variable is empty.")
        self._api_key = str(api_key).strip()
        self.base_url = str(base_url)
        self.timeout = float(timeout)

    def _post(self, form_fields: Mapping[str, Any]) -> bytes:
        body = urllib.parse.urlencode(form_fields).encode("utf-8")
        req = urllib.request.Request(
            self.base_url,
            data=body,
            headers={
                "Auth-Key": self._api_key,
                "User-Agent": "dfir-triage-ml-v2-curator/2.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read()

    def query_tag(self, tag: str, limit: int = 50) -> list[dict[str, Any]]:
        raw = self._post({"query": "get_taginfo", "tag": str(tag), "limit": int(limit)})
        payload = json.loads(raw.decode("utf-8"))
        if payload.get("query_status") not in ("ok", "tag_not_found", "no_results"):
            raise RuntimeError(f"MalwareBazaar get_taginfo failed for tag={tag!r}: {payload.get('query_status')!r}")
        return list(payload.get("data") or [])

    def download_sample_zip(self, sha256_hash: str) -> bytes:
        raw = self._post({"query": "get_file", "sha256_hash": str(sha256_hash).lower()})
        if not raw.startswith(b"PK\x03\x04"):
            raise RuntimeError(f"Expected password-protected zip payload for {sha256_hash}, got non-zip response")
        return raw


def verify_gate0_ready(
    vault_root: str | Path = DEFAULT_VAULT_ROOT,
    setup_script: str | Path = DEFAULT_SETUP_SCRIPT,
) -> Path:
    """Enforce OD-V2-07: `GATE0_SIGNED_OFF` marker must exist and `05_quarantine_vault_setup.sh preflight` must pass."""
    vroot = Path(vault_root).expanduser()
    marker = vroot / "GATE0_SIGNED_OFF"
    if not marker.is_file():
        raise PilotStagingError(
            f"BLOCKED (OD-V2-07): Gate 0 sign-off marker missing at {marker}. "
            "Refusing sample curation until Gate 0 checklist is signed off by Mokh."
        )
    sp = Path(setup_script)
    if not sp.is_file():
        raise FileNotFoundError(f"Vault setup script not found: {sp}")
    env = dict(os.environ, VAULT_ROOT=str(vroot))
    cp = subprocess.run(["bash", str(sp), "preflight"], env=env, capture_output=True, text=True, check=False)
    if cp.returncode != 0:
        err = (cp.stderr or cp.stdout or "").strip()
        raise PilotStagingError(f"BLOCKED (OD-V2-07): Vault preflight check failed: {err}")
    return vroot


def canonical_family_slug(raw_signature: str | None, tags: Sequence[str] | None = None) -> str:
    """Normalize MalwareBazaar signature / tag metadata into a canonical lowercase family identifier."""
    candidates: list[str] = []
    if raw_signature and str(raw_signature).strip().lower() not in ("", "none", "n/a", "unknown"):
        candidates.append(str(raw_signature).strip())
    for t in tags or ():
        tl = str(t).strip().lower()
        if tl and tl not in ("exe", "dll", "pe32", "pe32+", "signed", "unsigned", "32", "64", "malware"):
            candidates.append(str(t).strip())
    for raw in candidates:
        slug = re.sub(r"[^a-z0-9]+", "", raw.lower())
        if len(slug) >= 3:
            return canonicalize_family_name(slug)
    return "unknown_family"


def assign_near_dup_cluster(meta: Mapping[str, Any]) -> str:
    """Assign deterministic `ssdeep`/`tlsh`/`imphash` near-duplicate cluster identifier (`OD-V2-08`)."""
    imp = str(meta.get("imphash") or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", imp):
        return f"imp_{imp}"
    tlsh = str(meta.get("tlsh") or "").strip().upper()
    if len(tlsh) >= 16:
        return f"tlsh_{tlsh[:16]}"
    ssdeep = str(meta.get("ssdeep") or "").strip()
    if ":" in ssdeep:
        parts = ssdeep.split(":", 2)
        if len(parts) >= 2 and parts[0].isdigit():
            return f"ssdeep_{parts[0]}_{parts[1][:12]}"
    sha = str(meta.get("sha256_hash") or meta.get("sha256") or "").strip().lower()
    return f"sha_{sha[:16]}"


def _is_windows_pe_candidate(entry: Mapping[str, Any]) -> bool:
    """Accept ONLY standalone Windows .exe candidates (strictly exclude DLL/CPL/SYS/OCX/SCR/MSI/non-Windows)."""
    ftype = str(entry.get("file_type") or entry.get("file_type_mime") or "").lower().strip()
    fname = str(entry.get("file_name") or "").lower().strip()
    tags = {str(t).lower().strip() for t in (entry.get("tags") or ()) if t is not None}
    if any(fname.endswith(bad_ext) for bad_ext in _DISALLOWED_NON_EXE_EXTS):
        return False
    if any(bad in ftype for bad in ("dll", "cpl", "sys", "ocx", "scr", "msi", "elf", "apk", "macho", "pdf", "doc", "zip", "rar", "iso")):
        return False
    if "dll" in tags:
        return False
    return ("exe" in ftype or "pe32" in ftype) or fname.endswith(_WINDOWS_PE_EXTS)


def validate_standalone_runnable_exe_pe(payload_bytes: bytes) -> dict[str, Any]:
    """Verify in RAM via `pefile` that `payload_bytes` is a standalone Windows x86/x64 runnable .exe (NOT a DLL/driver)."""
    if not payload_bytes or len(payload_bytes) < 64 or payload_bytes[:2] != b"MZ":
        raise PilotStagingError("Invalid PE candidate: missing MZ DOS header")

    import pefile  # type: ignore

    try:
        pe = pefile.PE(data=payload_bytes, fast_load=True)
    except Exception as exc:
        raise PilotStagingError(f"Invalid PE candidate: pefile parse error ({exc})") from exc

    try:
        machine = int(getattr(pe.FILE_HEADER, "Machine", 0))
        if machine not in _VALID_X86_MACHINES:
            raise PilotStagingError(f"Unsupported PE Machine 0x{machine:04x}; require Windows x86/x64")
        if pe.is_dll():
            raise PilotStagingError("Rejected PE candidate: IMAGE_FILE_DLL flag set (DLLs cannot run standalone via Start-Process)")
        if pe.is_driver():
            raise PilotStagingError("Rejected PE candidate: kernel driver PE")
        if not pe.is_exe():
            raise PilotStagingError("Rejected PE candidate: IMAGE_FILE_EXECUTABLE_IMAGE flag missing")

        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            imp = pe.get_imphash()
            imphash = str(imp).lower() if imp else None
        except Exception:
            imphash = None
    finally:
        pe.close()

    pp_hash = None
    if importlib.util.find_spec("ppdeep") is not None:
        try:
            import ppdeep  # type: ignore

            pp_hash = ppdeep.hash(payload_bytes)
        except Exception:
            pp_hash = None

    tl_hash = None
    if importlib.util.find_spec("tlsh") is not None:
        try:
            import tlsh  # type: ignore

            tl_val = tlsh.hash(payload_bytes)
            tl_hash = tl_val if tl_val and tl_val != "TNULL" else None
        except Exception:
            tl_hash = None

    return {
        "machine": f"0x{machine:04x}",
        "is_exe": True,
        "is_dll": False,
        "imphash": imphash,
        "ppdeep": pp_hash,
        "tlsh": tl_hash,
    }


def _persistence_score(entry: Mapping[str, Any], family_slug: str) -> tuple[int, int]:
    tags = [str(t).lower() for t in (entry.get("tags") or ())]
    sig = str(entry.get("signature") or "").lower()
    blob = " ".join([family_slug, sig, *tags])
    hint_hits = sum(1 for tok in _PERSISTENCE_HINT_TOKENS if tok in blob)
    size = int(entry.get("file_size") or 0)
    reasonable_size = 1 if (16 * 1024 <= size <= 25 * 1024 * 1024) else 0
    return (hint_hits, reasonable_size)


def select_pilot_families(
    candidates_by_category: Mapping[str, Sequence[Mapping[str, Any]]],
    target_families: int = 7,
    max_per_family: int = 1,
    target_samples: int | None = None,
) -> list[dict[str, Any]]:
    """Select non-destructive standalone-.exe PE families across allowed categories (hard-blocking ransomware/wipers/worms)."""
    eff_target_samples = int(target_samples if target_samples is not None else target_families)
    eff_max_per_fam = max(1, int(max_per_family))

    seen_hashes: set[str] = set()
    seen_clusters: set[str] = set()
    family_counts: dict[str, int] = {}
    selected: list[dict[str, Any]] = []

    ranked_by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cat, items in candidates_by_category.items():
        if check_forbidden_malware_policy(sample_category=cat, require_allowlist=False) is not None:
            continue
        for raw in items:
            sha = str(raw.get("sha256_hash") or raw.get("sha256") or "").lower().strip()
            if not re.fullmatch(r"[0-9a-f]{64}", sha):
                continue
            if not _is_windows_pe_candidate(raw):
                continue
            fam = canonicalize_family_name(canonical_family_slug(raw.get("signature"), raw.get("tags")))
            if not fam or fam == "unknownfamily" or fam not in CANONICAL_ALLOWED_FAMILIES:
                continue
            if check_forbidden_malware_policy(
                sample_family=fam,
                sample_category=cat,
                tags=raw.get("tags") or (),
                raw_signature=raw.get("signature"),
                require_allowlist=True,
            ) is not None:
                continue
            cluster_id = assign_near_dup_cluster(raw)
            rec = dict(raw)
            rec["_category"] = cat
            rec["_sha256"] = sha
            rec["_family"] = fam
            rec["_cluster"] = cluster_id
            rec["_score"] = _persistence_score(raw, fam)
            ranked_by_cat[cat].append(rec)
        ranked_by_cat[cat].sort(key=lambda r: (r["_score"], r["_sha256"]), reverse=True)

    categories = list(candidates_by_category.keys())
    progress = True
    while len(selected) < eff_target_samples and progress:
        progress = False
        for cat in categories:
            if len(selected) >= eff_target_samples:
                break
            for rec in ranked_by_cat[cat]:
                sha = rec["_sha256"]
                fam = rec["_family"]
                clu = rec["_cluster"]
                cur_count = family_counts.get(fam, 0)
                is_new_fam = cur_count == 0
                if is_new_fam and len(family_counts) >= int(target_families):
                    continue
                if sha in seen_hashes or clu in seen_clusters or cur_count >= eff_max_per_fam:
                    continue
                seen_hashes.add(sha)
                seen_clusters.add(clu)
                family_counts[fam] = cur_count + 1
                selected.append(rec)
                progress = True
                break
    return selected


def _write_clean_sha256_manifest(archives_dir: Path, manifest_path: Path) -> None:
    lines: list[str] = []
    for p in sorted(archives_dir.iterdir(), key=lambda x: x.name):
        if p.is_file():
            digest = hashlib.sha256(p.read_bytes()).hexdigest().lower()
            lines.append(f"{digest}  {p.name}")
    manifest_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def build_pilot_batch_specs(
    curated_samples: Sequence[Mapping[str, Any]],
    n_control_boots: int = 3,
    dwell_seconds: int = 120,
) -> list[dict[str, Any]]:
    """Build Gate-0-validated Stage A Pilot batch (`n_control_boots` + executed-first paired `executed` & `dormant` runs)."""
    batch: list[dict[str, Any]] = []
    for c_idx in range(1, int(n_control_boots) + 1):
        spec = StageRunSpec(
            run_id=f"pilot_ctrl_{c_idx:02d}",
            stratum="control",
            benign_profile_id=f"B_dev_{c_idx:02d}",
            dwell_seconds=dwell_seconds,
            execute_payload=False,
            split_pool="dev",
        )
        validate_stage_run_spec(spec)
        batch.append({"spec": spec.__dict__, "vault_file": None})

    for s_idx, rec in enumerate(curated_samples, start=1):
        fam = str(rec["sample_family"])
        cat = str(rec.get("category") or "")
        tags = tuple(str(t) for t in (rec.get("tags") or ()))
        assert_allowed_malware_policy(sample_family=fam, sample_category=cat, tags=tags, raw_signature=rec.get("raw_signature"))

        sha = str(rec["sample_sha256"])
        vault_file = str(rec["vault_archive_path"])
        pair_id = f"pair_pilot_{s_idx:02d}_{fam}"
        staged_path = rf"C:\Users\Public\Downloads\{fam}_updater_{sha[:8]}.exe"
        benign_profile = f"B_dev_{((s_idx - 1) % 20) + 1:02d}"

        # Executed-first gating: schedule executed before dormant so duds never waste dormant boots
        for stratum in ("executed", "dormant"):
            spec = StageRunSpec(
                run_id=f"pilot_{s_idx:02d}_{fam}_{stratum}",
                stratum=stratum,
                benign_profile_id=benign_profile,
                dwell_seconds=dwell_seconds,
                staging_target_path=staged_path,
                sample_sha256=sha,
                sample_family=fam,
                sample_category=cat or None,
                sample_tags=tags,
                pair_group_id=pair_id,
                execute_payload=(stratum == "executed"),
                gate0_signed_off=True,
                dedicated_host_user_verified=True,
                split_pool="dev",
            )
            validate_stage_run_spec(spec)
            batch.append({
                "spec": spec.__dict__,
                "vault_file": vault_file,
                "archive_password": "infected",
                "sample_category": rec.get("category"),
                "near_dup_cluster_id": rec.get("near_dup_cluster_id"),
            })
    return batch


def curate_pilot_vault_and_batch(
    vault_root: str | Path = DEFAULT_VAULT_ROOT,
    setup_script: str | Path = DEFAULT_SETUP_SCRIPT,
    target_families: int = 7,
    n_control_boots: int = 3,
    dwell_seconds: int = 120,
    query_limit: int = 40,
    archive_password: str = "infected",
    client: SampleFeedClient | None = None,
    plan_only: bool = False,
    max_per_family: int = 1,
    target_samples: int | None = None,
    min_families: int = 6,
) -> dict[str, Any]:
    """Curate non-destructive standalone-.exe families into `0400` vault archives & emit `stage_a_pilot_batch.json`."""
    vroot = verify_gate0_ready(vault_root=vault_root, setup_script=setup_script)
    archives_dir = vroot / "archives"
    archives_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(archives_dir, 0o700)

    if client is None:
        api_key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
        if not api_key:
            raise RuntimeError(
                "ABUSECH_AUTH_KEY environment variable is required to query MalwareBazaar API (never hardcode keys)."
            )
        client = MalwareBazaarClient(api_key=api_key)

    candidates_by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cat, tags in CATEGORY_SEARCH_TAGS:
        for tag in tags:
            rows = client.query_tag(tag, limit=query_limit)
            candidates_by_cat[cat].extend(rows)

    selected = select_pilot_families(
        candidates_by_cat,
        target_families=target_families,
        max_per_family=max_per_family,
        target_samples=target_samples,
    )
    if len({r["_family"] for r in selected}) < int(min_families):
        raise RuntimeError(
            f"Expected >= {min_families} distinct non-destructive standalone-.exe families, curated only {len(selected)}."
        )

    curated_records: list[dict[str, Any]] = []
    for rec in selected:
        sha = rec["_sha256"]
        fam = rec["_family"]
        cat = rec["_category"]
        assert_allowed_malware_policy(
            sample_family=fam,
            sample_category=cat,
            tags=rec.get("tags") or (),
            raw_signature=rec.get("signature"),
        )
        archive_path = archives_dir / f"{sha}.zip"
        ssdeep_val = rec.get("ssdeep")
        tlsh_val = rec.get("tlsh")
        imphash = rec.get("imphash")

        if not plan_only:
            tmp_zip = archives_dir / f".tmp_{sha}.zip"
            src_to_read = archive_path if archive_path.exists() else tmp_zip
            if not archive_path.exists():
                zip_bytes = client.download_sample_zip(sha)
                tmp_zip.write_bytes(zip_bytes)
            try:
                # Decrypt strictly in RAM to verify SHA-256 & standalone runnable .exe PE gate BEFORE saving to vault
                payload_ram = read_vault_payload_in_memory(src_to_read, password=archive_password)
                ram_sha = hashlib.sha256(payload_ram).hexdigest().lower()
                if ram_sha != sha:
                    raise PilotStagingError(f"Downloaded payload SHA-256 mismatch for {fam}: {ram_sha} != {sha}")
                pe_info = validate_standalone_runnable_exe_pe(payload_ram)
            except Exception:
                if tmp_zip.exists():
                    tmp_zip.unlink()
                raise

            if tmp_zip.exists():
                tmp_zip.replace(archive_path)
            os.chmod(archive_path, 0o400)
            imphash = imphash or pe_info.get("imphash")
            ssdeep_val = ssdeep_val or pe_info.get("ppdeep")
            tlsh_val = tlsh_val or pe_info.get("tlsh")

        curated_records.append({
            "sample_sha256": sha,
            "sample_family": fam,
            "raw_signature": rec.get("signature"),
            "category": cat,
            "file_name": rec.get("file_name"),
            "file_type": rec.get("file_type"),
            "file_size": rec.get("file_size"),
            "imphash": str(imphash).lower() if imphash else None,
            "tlsh": tlsh_val,
            "ssdeep": ssdeep_val,
            "near_dup_cluster_id": rec["_cluster"],
            "tags": list(rec.get("tags") or ()),
            "vault_archive_path": str(archive_path),
            "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest().lower() if archive_path.exists() else None,
            "split_pool": "dev",
            "pilot_only_exclude_from_blind_test": True,
        })

    if not plan_only:
        _write_clean_sha256_manifest(archives_dir, vroot / "sample_manifest.sha256")
        verify_gate0_ready(vault_root=vroot, setup_script=setup_script)

    manifest_out = {
        "generated_at_utc": utc_now_iso(),
        "vault_root": str(vroot),
        "plan_only": bool(plan_only),
        "n_families": len({r["sample_family"] for r in curated_records}),
        "n_samples": len(curated_records),
        "forbidden_policy_enforced": sorted(FORBIDDEN_MALWARE_FAMILIES_AND_TAGS),
        "samples": curated_records,
    }
    vault_manifest_path = write_json(manifest_out, vroot / "vault_manifest.json")

    batch = build_pilot_batch_specs(
        curated_records,
        n_control_boots=n_control_boots,
        dwell_seconds=dwell_seconds,
    )
    batch_payload = {
        "generated_at_utc": utc_now_iso(),
        "vault_manifest_path": str(vault_manifest_path),
        "n_control_boots": int(n_control_boots),
        "n_families": len({r["sample_family"] for r in curated_records}),
        "n_samples": len(curated_records),
        "n_total_runs": len(batch),
        "runs": batch,
    }
    batch_path = write_json(batch_payload, vroot / "stage_a_pilot_batch.json")
    return {
        "vault_manifest_path": str(vault_manifest_path),
        "batch_path": str(batch_path),
        "n_families": len({r["sample_family"] for r in curated_records}),
        "n_samples": len(curated_records),
        "n_total_runs": len(batch),
        "families": sorted({r["sample_family"] for r in curated_records}),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate-0-guarded MalwareBazaar vault curator & paired Stage A/B builder.")
    parser.add_argument("--vault-root", type=Path, default=DEFAULT_VAULT_ROOT)
    parser.add_argument("--setup-script", type=Path, default=DEFAULT_SETUP_SCRIPT)
    parser.add_argument("--target-families", type=int, default=7, help="Number of distinct non-destructive PE families (7 pilot, up to 60 Stage B)")
    parser.add_argument("--max-per-family", type=int, default=1)
    parser.add_argument("--target-samples", type=int, default=None)
    parser.add_argument("--min-families", type=int, default=6)
    parser.add_argument("--n-control-boots", type=int, default=3)
    parser.add_argument("--dwell-seconds", type=int, default=120)
    parser.add_argument("--query-limit", type=int, default=40)
    parser.add_argument("--archive-password", default="infected")
    parser.add_argument("--plan-only", action="store_true", help="Query API metadata and emit plan without downloading archives")
    args = parser.parse_args(list(argv) if argv is not None else None)

    summary = curate_pilot_vault_and_batch(
        vault_root=args.vault_root,
        setup_script=args.setup_script,
        target_families=args.target_families,
        n_control_boots=args.n_control_boots,
        dwell_seconds=args.dwell_seconds,
        query_limit=args.query_limit,
        archive_password=args.archive_password,
        plan_only=args.plan_only,
        max_per_family=args.max_per_family,
        target_samples=args.target_samples,
        min_families=args.min_families,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
