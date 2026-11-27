"""Zero-SSH / Zero-Guest-Agent offline run staging builder (`OD-V2-04`, `OD-V2-05`, `OD-V2-07`, `OD-V2-09`).

Because `01_firewall_win11_isolated.sh` drops all host-to-guest traffic on `virbr1` and
`02_domain_xml_hardening.md` removes `qemu-guest-agent`, SPICE clipboard/file transfer, and shared folders,
runs stage their deterministic manifest, procedural benign workload, and (after Gate 0 sign-off)
paired `dormant` / `dormant_batch` / `executed` payloads via a per-run **read-only ISO-9660 virtual CD-ROM**
(`DFIR_STAGE`) attached before `virsh start win11`.

Safety policy:
- Enforces centralized fail-closed `FORBIDDEN_MALWARE_FAMILIES_AND_TAGS` blocking ransomware, wipers,
  and self-propagating worms across single-sample and dev-only `dormant_batch` specs.
- `dormant_batch` is strictly forbidden on `split_pool == "blind_test"` (blind-test dormant stays 1 sample/boot)
  and stages files inside `benign_workload.ps1` with `stratum="dormant_batch"` so the pre-baked
  `C:\\DFIR-Bootstrap\\Invoke-StagePayload.ps1` works without re-baking `win11_base.qcow2`.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Any, Mapping, Sequence
import zipfile

from src.utils.repro import utc_now_iso
from src.v2.benign_generator_v2 import generate_benign_workload_bundle

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.I)
DORMANT_BATCH_MAX: int = 16
SUPERVISOR_APPROVAL_REF = (
    "Supervisor Marawan (AASTMT) written approval 2026-11-23 + comparative study addendum 2026-11-25 — "
    "'Research Approval Request: Controlled Malware Analysis for DFIR Triage' "
    "(Institutional Ethics Review: Not Required — Waived by Supervisor; hard exclusion of ransomware/wipers/worms)"
)

# Fail-closed blocklist covering ransomware, wipers, and self-propagating worms (exact tokens/slugs).
FORBIDDEN_MALWARE_FAMILIES_AND_TAGS: frozenset[str] = frozenset({
    # Ransomware
    "ransom", "ransomware", "lockbit", "blackcat", "alphv", "conti", "ryuk", "revil", "sodinokibi",
    "stop", "djvu", "stopdjvu", "phobos", "makop", "dharma", "crysis", "wannacry", "wcry", "wannacrypt",
    "cerber", "gandcrab", "maze", "egregor", "netwalker", "clop", "cl0p", "blackbasta", "royal", "akira",
    "medusa", "medusalocker", "babuk", "hive", "ragnarlocker", "darkside", "blackmatter", "avaddon", "pysa",
    "rhysida", "bianlian", "qilin", "cactus", "8base", "snatch", "mallox", "zeppelin", "avoslocker",
    "teslacrypt", "jigsaw", "badrabbit", "petya", "samsam", "globeimposter", "scarab", "cryptolocker",
    "cryptowall", "locker", "play", "lynx", "chaos", "cuba", "mimic", "blackbyte", "hellokitty",
    "lorenz", "nokoyawa", "xorist", "locky", "filecoder", "thanos", "trigona", "ransomhub",
    # Wipers
    "wiper", "diskwiper", "mbrwiper", "notpetya", "hermeticwiper", "caddywiper", "whispergate",
    "isaacwiper", "acidrain", "swiftwiper", "doublezero", "shamoon", "disttrack", "olympicdestroyer",
    "killdisk", "stonedrill", "zerocleare", "dustman", "crywiper", "azov",
    # Self-propagating worms / file-infectors (whole tokens)
    "worm", "usb_worm", "usbworm", "smb_worm", "smbworm", "networm", "conficker", "downadup",
    "sality", "virut", "ramnit", "stuxnet", "mydoom", "sobig", "blaster", "sasser", "nimda",
    "slammer", "wannamine", "eternalblue", "xworm", "brontok", "vobfus", "gamarue", "andromeda",
    "jenxcus", "neshta", "parite", "expiro", "phorpiex", "dorkbot", "raspberryrobin", "blackshades",
    "lemonduck", "tofsee", "bondat",
    # USB-spreader / ransomware-module exclusion
    "lime", "limerat",
})

# Substring stems (excludes whole-token blocks like "stop", "play", "lynx", "chaos" so benign words like "desktop"/"display" pass).
FORBIDDEN_SUBSTRING_STEMS: tuple[str, ...] = (
    "ransom", "wiper", "worm", "lockbit", "wannacry", "notpetya", "hermeticwiper",
    "caddywiper", "whispergate", "conficker", "sality", "virut", "ramnit", "djvu",
    "phobos", "makop", "blackcat", "alphv", "revil", "conti", "ryuk", "clop",
    "blackbasta", "cryptolocker",
)

# Canonical alias map so closely linked names/aliases share ONE grouping unit for splits and family caps.
FAMILY_ALIAS_TO_CANONICAL: dict[str, str] = {
    "lumma": "lumma",
    "lummac2": "lumma",
    "lummastealer": "lumma",
    "warzone": "warzone",
    "warzonerat": "warzone",
    "avemaria": "warzone",
    "redline": "redline",
    "redlinestealer": "redline",
    "raccoon": "raccoon",
    "raccoonstealer": "raccoon",
    "remcos": "remcos",
    "remcosrat": "remcos",
    "quasar": "quasar",
    "quasarrat": "quasar",
    "orcus": "orcus",
    "orcusrat": "orcus",
    "nanocore": "nanocore",
    "nanocorerat": "nanocore",
    "buer": "buer",
    "buerloader": "buer",
    "aurora": "aurora",
    "aurorastealer": "aurora",
    "revenge": "revenge",
    "revengerat": "revenge",
    "gh0st": "gh0st",
    "ghostrat": "gh0st",
    "formbook": "formbook",
    "xloader": "formbook",
    "arkei": "vidar",
    "vidar": "vidar",
    "recordbreaker": "raccoon",
}

# Reviewed positive allowlist (normalized lowercase alphanumeric slugs).
# Note: njrat / bladabindi / qakbot / emotet / trickbot are intentionally excluded pending supervisor review.
# lime / limerat removed (USB spreader / ransomware modules).
ALLOWED_FAMILIES: frozenset[str] = frozenset({
    # InfoStealers
    "redline", "redlinestealer", "lummac2", "lumma", "lummastealer", "agenttesla", "vidar",
    "raccoon", "raccoonstealer", "formbook", "xloader", "snakekeylogger", "lokibot",
    "metastealer", "risepro", "stealc", "rhadamanthys", "aurora", "aurorastealer",
    "phoenixkeylogger", "masslogger", "azorult", "arkei", "marsstealer", "predatorthethief",
    "recordbreaker", "whitesnake",
    # Non-worm RATs / Backdoors
    "asyncrat", "remcos", "remcosrat", "quasar", "quasarrat", "dcrat", "venomrat",
    "nanocore", "nanocorerat", "darkcomet", "orcus", "orcusrat", "bitrat",
    "warzone", "warzonerat", "avemaria", "phantomrat", "poisonivy", "netwire",
    "gh0st", "ghostrat", "revenge", "revengerat", "cobaltstrike",
    # Non-worm Loaders / Droppers
    "smokeloader", "amadey", "privateloader", "guloader", "bumblebee", "systembc",
    "purecrypter", "hijackloader", "latrodectus", "dbatloader", "modiloader", "bazarloader",
    "buer", "buerloader", "zloader", "icedid", "matanbuchus", "pikabot", "darkgate", "pony",
    # Coinminers / Clippers
    "xmrig", "silentcryptominer", "clipbanker", "laplasclipper", "coinminer", "cryptobot",
})


class PilotStagingError(RuntimeError):
    """Raised when a staging request violates Gate 0, safety blocklist, or paired-stratum invariants."""


def normalize_family_slug(raw: str | None) -> str:
    """Normalize a family/signature string to lowercase ASCII alphanumeric characters."""
    return re.sub(r"[^a-z0-9]+", "", str(raw or "").strip().lower())


def canonicalize_family_name(raw: str | None) -> str:
    """Map normalized family/signature aliases (e.g., `lummac2`/`avemaria`/`xloader`) to ONE canonical key."""
    slug = normalize_family_slug(raw)
    return FAMILY_ALIAS_TO_CANONICAL.get(slug, slug)


CANONICAL_ALLOWED_FAMILIES: frozenset[str] = frozenset(
    canonicalize_family_name(f) for f in ALLOWED_FAMILIES
)


def check_forbidden_malware_policy(
    sample_family: str | None = None,
    sample_category: str | None = None,
    tags: Sequence[str] = (),
    raw_signature: str | None = None,
    *,
    require_allowlist: bool = True,
) -> str | None:
    """Fail-closed policy check: enforce blocklist (ransomware/wiper/worm) and ALLOWED_FAMILIES allowlist."""
    fields: list[tuple[str, str]] = []
    if sample_family and str(sample_family).strip():
        fields.append(("sample_family", str(sample_family)))
    if sample_category and str(sample_category).strip():
        fields.append(("sample_category", str(sample_category)))
    if raw_signature and str(raw_signature).strip():
        fields.append(("raw_signature", str(raw_signature)))
    for t in tags or ():
        if t is not None and str(t).strip():
            fields.append(("tag", str(t)))

    if not fields:
        return "Unlabeled malware policy metadata rejected (fail-closed: all family/category/tags/signature empty)"

    for fname, val in fields:
        low = val.strip().lower()
        tokens = [tok for tok in re.split(r"[^a-z0-9_]+", low) if tok]
        sub_tokens = [tok for tok in re.split(r"[^a-z0-9]+", low) if tok]
        slug = re.sub(r"[^a-z0-9]+", "", low)
        all_candidates = set(tokens) | set(sub_tokens) | ({slug} if slug else set())

        for cand in all_candidates:
            if cand in FORBIDDEN_MALWARE_FAMILIES_AND_TAGS:
                return f"Forbidden malware policy match ({fname}={val!r}, token={cand!r})"
            for stem in FORBIDDEN_SUBSTRING_STEMS:
                if stem in cand:
                    return f"Forbidden malware policy match ({fname}={val!r}, stem={stem!r})"

    if require_allowlist:
        fam_source = sample_family if (sample_family and str(sample_family).strip()) else raw_signature
        norm_fam = normalize_family_slug(fam_source)
        if not norm_fam:
            return "Unlabeled sample rejected (fail-closed: missing sample_family/raw_signature)"
        if norm_fam not in ALLOWED_FAMILIES:
            return (
                f"Sample family {fam_source!r} (normalized={norm_fam!r}) is NOT in reviewed ALLOWED_FAMILIES"
            )

    return None


def assert_allowed_malware_policy(
    sample_family: str | None = None,
    sample_category: str | None = None,
    tags: Sequence[str] = (),
    raw_signature: str | None = None,
) -> None:
    """Fail closed with `PilotStagingError` if sample metadata matches a forbidden category/family."""
    reason = check_forbidden_malware_policy(
        sample_family=sample_family,
        sample_category=sample_category,
        tags=tags,
        raw_signature=raw_signature,
    )
    if reason is not None:
        raise PilotStagingError(
            f"BLOCKED (Supervisor Marawan safety policy — zero ransomware/wiper/worm): {reason}"
        )


@dataclass(frozen=True)
class StageRunSpec:
    """Deterministic specification for one zero-SSH Win11 VM run."""

    run_id: str
    stratum: str  # "control" | "dormant" | "executed" | "dormant_batch"
    benign_profile_id: str
    dwell_seconds: int = 120
    staging_target_path: str | None = None
    sample_sha256: str | None = None
    sample_family: str | None = None
    pair_group_id: str | None = None
    execute_payload: bool = False
    gate0_signed_off: bool = False
    dedicated_host_user_verified: bool = False
    supervisor_approval_ref: str = SUPERVISOR_APPROVAL_REF
    sample_category: str | None = None
    sample_tags: tuple[str, ...] = ()
    split_pool: str = "dev"
    batch_samples: tuple[dict[str, Any], ...] = ()


def validate_stage_run_spec(spec: StageRunSpec) -> None:
    """Enforce Gate 0 (`OD-V2-07`), safety exclusion policy, and paired/batch staging invariants."""
    st = str(spec.stratum).strip().lower()
    if st not in ("control", "dormant", "executed", "dormant_batch"):
        raise PilotStagingError(
            f"Invalid stratum {spec.stratum!r}; must be 'control', 'dormant', 'executed', or 'dormant_batch'"
        )
    if int(spec.dwell_seconds) < 10 or int(spec.dwell_seconds) > 1800:
        raise PilotStagingError(f"dwell_seconds must be in [10, 1800], got {spec.dwell_seconds}")

    if st == "control":
        if spec.execute_payload:
            raise PilotStagingError("control stratum must have execute_payload=False")
        if spec.sample_sha256 is not None:
            raise PilotStagingError("control stratum must not stage any malware sample_sha256")
        if spec.batch_samples:
            raise PilotStagingError("control stratum must not carry batch_samples")
        return

    # Malware runs -> enforce Gate 0 & Supervisor Marawan (AASTMT) conditions
    if not spec.gate0_signed_off:
        raise PilotStagingError(
            f"Gate 0 (OD-V2-07) is NOT signed off: refusing to stage {st!r} run {spec.run_id!r}. "
            "Complete NEG-01..NEG-10, base hash check, vault verify, and Mokh sign-off first."
        )
    if not spec.dedicated_host_user_verified:
        raise PilotStagingError(
            "ASUS host condition (OD-V2-07b) not verified: dedicated isolated user account with zero personal "
            "credentials/sensitive data must be verified before staging malware runs."
        )

    if st == "dormant_batch":
        pool = str(spec.split_pool).strip().lower()
        if pool != "dev":
            raise PilotStagingError(
                f"dormant_batch is strictly restricted to split_pool='dev' (got {spec.split_pool!r}); "
                "blind_test dormant runs MUST be 1 sample per boot."
            )
        if spec.execute_payload:
            raise PilotStagingError("dormant_batch must have execute_payload=False")
        items = list(spec.batch_samples or ())
        if not (1 <= len(items) <= DORMANT_BATCH_MAX):
            raise PilotStagingError(
                f"dormant_batch requires 1..{DORMANT_BATCH_MAX} samples per overlay, got {len(items)}"
            )
        seen_shas: set[str] = set()
        seen_paths: set[str] = set()
        for idx, item in enumerate(items):
            sha = str(item.get("sample_sha256") or "").strip().lower()
            tpath = str(item.get("staging_target_path") or "").strip()
            pid = str(item.get("pair_group_id") or "").strip()
            if not _SHA256_RE.match(sha):
                raise PilotStagingError(f"batch_samples[{idx}] invalid 64-hex sample_sha256: {sha!r}")
            if not tpath.lower().startswith("c:\\") or not tpath.lower().endswith(".exe"):
                raise PilotStagingError(
                    f"batch_samples[{idx}] staging_target_path must be a C:\\...\\.exe path, got {tpath!r}"
                )
            if not pid:
                raise PilotStagingError(f"batch_samples[{idx}] missing pair_group_id")
            assert_allowed_malware_policy(
                sample_family=item.get("sample_family"),
                sample_category=item.get("sample_category"),
                tags=item.get("sample_tags") or item.get("tags") or (),
                raw_signature=item.get("raw_signature"),
            )
            if sha in seen_shas:
                raise PilotStagingError(f"Duplicate sample_sha256 in dormant_batch: {sha}")
            if tpath.lower() in seen_paths:
                raise PilotStagingError(f"Duplicate staging_target_path in dormant_batch: {tpath}")
            seen_shas.add(sha)
            seen_paths.add(tpath.lower())
        return

    # Single-sample dormant or executed run
    assert_allowed_malware_policy(
        sample_family=spec.sample_family,
        sample_category=spec.sample_category,
        tags=spec.sample_tags or (),
    )
    if not spec.sample_sha256 or not _SHA256_RE.match(str(spec.sample_sha256)):
        raise PilotStagingError(f"Valid 64-hex sample_sha256 required for {st!r} run, got {spec.sample_sha256!r}")
    if not spec.pair_group_id or not str(spec.pair_group_id).strip():
        raise PilotStagingError("pair_group_id required to pair dormant/executed runs (OD-V2-05/09)")
    if not spec.staging_target_path or not str(spec.staging_target_path).lower().startswith("c:\\"):
        raise PilotStagingError(
            f"staging_target_path must be an explicit C:\\ path shared by paired dormant & executed runs, "
            f"got {spec.staging_target_path!r}"
        )

    if st == "dormant" and spec.execute_payload:
        raise PilotStagingError("dormant stratum must have execute_payload=False (stage on disk without execution)")
    if st == "executed" and not spec.execute_payload:
        raise PilotStagingError("executed stratum must have execute_payload=True")


def generate_guest_bootstrapper_ps1() -> str:
    """Return the pre-baked in-guest PowerShell bootstrapper (`C:\\DFIR-Bootstrap\\Invoke-StagePayload.ps1`)."""
    return r"""# Invoke-StagePayload.ps1 — Zero-SSH / Zero-Guest-Agent Stage A Pilot In-Guest Bootstrapper
$ErrorActionPreference = "Stop"
$vol = Get-Volume | Where-Object { $_.FileSystemLabel -eq "DFIR_STAGE" -and $_.DriveLetter } | Select-Object -First 1
if (-not $vol) {
    exit 0
}
$stageRoot = "$($vol.DriveLetter):\"
$manifestPath = Join-Path $stageRoot "run_manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath)) {
    exit 0
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

# 1. Run deterministic benign workload if present
$benignScript = Join-Path $stageRoot "benign_workload.ps1"
if (Test-Path -LiteralPath $benignScript) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $benignScript -ProfileId $manifest.benign_profile_id
}

# 2. For dormant or executed strata, copy payload to exact matching initial staging_target_path and verify SHA-256
if ($manifest.stratum -in @("dormant", "executed")) {
    $payloadSrc = Join-Path $stageRoot "payload.bin"
    $targetPath = [string]$manifest.staging_target_path
    $targetDir = Split-Path -Parent $targetPath
    if (-not (Test-Path -LiteralPath $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $payloadSrc -Destination $targetPath -Force
    $actualHash = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $manifest.sample_sha256.ToLowerInvariant()) {
        throw "SHA-256 mismatch on staged payload: $actualHash != $($manifest.sample_sha256)"
    }
    if ($manifest.stratum -eq "executed" -and $manifest.execute_payload -eq $true) {
        Start-Process -FilePath $targetPath -WorkingDirectory $targetDir
    }
}

# 3. Wait dwell_seconds, flush NTFS volume cache, and power off cleanly before watchdog hard kill
$dwell = if ($manifest.dwell_seconds) { [int]$manifest.dwell_seconds } else { 120 }
Start-Sleep -Seconds $dwell
Write-VolumeCache -DriveLetter C -ErrorAction SilentlyContinue
if ($manifest.auto_poweroff -ne $false) {
    Stop-Computer -Force
}
"""


def _build_minimal_iso9660(volume_label: str, files: dict[str, bytes]) -> bytes:
    """Build a deterministic minimal ISO-9660 Level-1 read-only image in pure Python (zero host tools required)."""
    sector_size = 2048
    label = volume_label.upper()[:32].ljust(32)

    sorted_names = sorted(files.keys())
    next_sector = 20
    file_sectors: dict[str, tuple[int, int]] = {}
    for name in sorted_names:
        data = files[name]
        n_sec = max(1, (len(data) + sector_size - 1) // sector_size)
        file_sectors[name] = (next_sector, len(data))
        next_sector += n_sec

    total_sectors = next_sector
    image = bytearray(total_sectors * sector_size)

    def _both32(val: int) -> bytes:
        return struct.pack("<I", val) + struct.pack(">I", val)

    def _both16(val: int) -> bytes:
        return struct.pack("<H", val) + struct.pack(">H", val)

    def _dir_record(ident: bytes, extent_lba: int, data_len: int, flags: int) -> bytes:
        id_len = len(ident)
        pad = 1 if (id_len % 2 == 0) else 0
        rec_len = 33 + id_len + pad
        rec = bytearray(rec_len)
        rec[0] = rec_len
        rec[1] = 0
        rec[2:10] = _both32(extent_lba)
        rec[10:18] = _both32(data_len)
        rec[18:25] = bytes([126, 11, 25, 0, 0, 0, 0])  # 2026-11-25 UTC
        rec[25] = flags
        rec[28:32] = _both16(1)
        rec[32] = id_len
        rec[33 : 33 + id_len] = ident
        return bytes(rec)

    root_dir = bytearray()
    root_dir.extend(_dir_record(b"\x00", 19, sector_size, 0x02))
    root_dir.extend(_dir_record(b"\x01", 19, sector_size, 0x02))
    for idx, name in enumerate(sorted_names):
        lba, dlen = file_sectors[name]
        stem = re.sub(r"[^A-Z0-9_]", "_", Path(name).stem.upper())[:8] or f"FILE{idx}"
        ext = re.sub(r"[^A-Z0-9_]", "", Path(name).suffix.upper().lstrip("."))[:3]
        iso_id = (f"{stem}.{ext};1" if ext else f"{stem}.;1").encode("ascii")
        root_dir.extend(_dir_record(iso_id, lba, dlen, 0x00))
    image[19 * sector_size : 19 * sector_size + len(root_dir)] = root_dir[:sector_size]

    pt = bytearray(10)
    pt[0] = 1
    pt[1] = 0
    pt[2:6] = struct.pack("<I", 19)
    pt[6:8] = struct.pack("<H", 1)
    pt[8] = 0
    image[18 * sector_size : 18 * sector_size + len(pt)] = pt

    pvd = bytearray(sector_size)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[8:40] = b"WIN11_ISOLATED_STAGE".ljust(32)
    pvd[40:72] = label.encode("ascii")
    pvd[80:88] = _both32(total_sectors)
    pvd[120:124] = _both16(1)
    pvd[124:128] = _both16(1)
    pvd[128:132] = _both16(sector_size)
    pvd[132:140] = _both32(len(pt))
    pvd[140:144] = struct.pack("<I", 18)
    root_entry = _dir_record(b"\x00", 19, sector_size, 0x02)
    pvd[156 : 156 + 34] = root_entry
    pvd[881] = 1
    image[16 * sector_size : 17 * sector_size] = pvd

    term = bytearray(sector_size)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    image[17 * sector_size : 18 * sector_size] = term

    for name in sorted_names:
        lba, dlen = file_sectors[name]
        start = lba * sector_size
        image[start : start + dlen] = files[name]

    return bytes(image)


ISOLATED_NET_PREAMBLE_PS1 = """# Isolated static network configuration (win11-isolated -> inetsim-vm 192.168.150.10)
Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
    netsh interface ip set address name="$($_.Name)" static 192.168.150.50 255.255.255.0 192.168.150.10 | Out-Null
    netsh interface ip set dns name="$($_.Name)" static 192.168.150.10 | Out-Null
}
Start-Sleep -Seconds 5
"""


def _inject_isolated_net_preamble(script_text: str) -> str:
    """Inject static `192.168.150.50` -> `192.168.150.10` networking while preserving leading `param(...)`."""
    txt = str(script_text)
    if "192.168.150.50" in txt and "192.168.150.10" in txt:
        return txt

    m = re.match(r"^(?:\s*(?:#[^\n]*(?:\n|$)|\n))*param\s*\(", txt, flags=re.IGNORECASE)
    if m:
        pos = m.end()
        depth = 1
        in_sq = False
        in_dq = False
        n = len(txt)
        while pos < n and depth > 0:
            ch = txt[pos]
            if in_sq:
                if ch == "'":
                    in_sq = False
            elif in_dq:
                if ch == "`" and pos + 1 < n:
                    pos += 1
                elif ch == '"':
                    in_dq = False
            else:
                if ch == "'":
                    in_sq = True
                elif ch == '"':
                    in_dq = True
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            pos += 1
        if depth == 0:
            nl = txt.find("\n", pos)
            insert_at = (nl + 1) if nl != -1 else pos
            prefix = txt[:insert_at]
            if prefix and not prefix.endswith("\n"):
                prefix += "\n"
            return prefix + ISOLATED_NET_PREAMBLE_PS1 + txt[insert_at:]

    return ISOLATED_NET_PREAMBLE_PS1 + txt


def read_vault_payload_in_memory(
    vault_file: str | Path,
    password: str | bytes | None = "infected",
) -> bytes:
    """Read a raw or encrypted `.zip` vault sample strictly into RAM (zero host-disk plaintext writes)."""
    vpath = Path(vault_file)
    if not vpath.exists():
        raise FileNotFoundError(f"Vault sample file not found: {vpath}")

    with vpath.open("rb") as fh:
        magic = fh.read(4)

    if magic != b"PK\x03\x04":
        return vpath.read_bytes()

    pwd_str: str | None
    pwd_bytes: bytes | None
    if password is None or password == "" or password == b"":
        pwd_str = None
        pwd_bytes = None
    elif isinstance(password, bytes):
        pwd_bytes = password
        pwd_str = password.decode("utf-8", errors="replace")
    else:
        pwd_str = str(password)
        pwd_bytes = pwd_str.encode("utf-8")

    with zipfile.ZipFile(vpath, "r") as zf:
        members = [zi for zi in zf.infolist() if not zi.is_dir()]
        if len(members) != 1:
            raise PilotStagingError(
                f"Encrypted vault archive {vpath.name!r} must contain exactly 1 payload file, found {len(members)}"
            )
        member_name = members[0].filename
        if not member_name or member_name.startswith(("/", "\\")) or "\\" in member_name or ".." in Path(member_name).parts:
            raise PilotStagingError(f"Unsafe zip member path in vault archive: {member_name!r}")

    if importlib.util.find_spec("pyzipper") is not None:
        import pyzipper  # type: ignore

        try:
            with pyzipper.AESZipFile(vpath, "r") as pzf:
                if pwd_bytes is not None:
                    pzf.setpassword(pwd_bytes)
                return pzf.read(member_name)
        except Exception as exc:
            raise PilotStagingError(f"Failed to decrypt vault archive {vpath.name!r} via pyzipper: {exc}") from exc

    try:
        with zipfile.ZipFile(vpath, "r") as zf:
            return zf.read(member_name, pwd=pwd_bytes)
    except NotImplementedError:
        pass
    except RuntimeError as exc:
        if "compression method is not supported" not in str(exc).lower():
            raise PilotStagingError(f"Failed to decrypt vault archive {vpath.name!r}: {exc}") from exc

    bsdtar_bin = shutil.which("bsdtar")
    if not bsdtar_bin:
        raise PilotStagingError(
            f"AES-encrypted vault archive {vpath.name!r} requires either `pyzipper` or `bsdtar` for RAM decryption."
        )
    cmd = [bsdtar_bin]
    if pwd_str is not None:
        cmd.extend(["--passphrase", pwd_str])
    cmd.extend(["-xOf", str(vpath), member_name])
    cp = subprocess.run(cmd, check=False, capture_output=True)
    if cp.returncode != 0:
        err = cp.stderr.decode("utf-8", errors="replace").strip()
        raise PilotStagingError(f"bsdtar RAM decryption failed for {vpath.name!r}: {err}")
    return cp.stdout


def _clean_iso_relpath(raw_name: str) -> str:
    name = str(raw_name).strip()
    if not name or name.startswith(("/", "\\")) or "\\" in name:
        raise ValueError(f"ISO staging path must use clean relative POSIX segments, got {raw_name!r}")
    parts = name.split("/")
    if any(not p or p in (".", "..") for p in parts):
        raise ValueError(f"Unsafe ISO staging path segment in {raw_name!r}")
    return "/".join(parts)


def build_stage_iso(iso_path: str | Path, volume_label: str, files: Mapping[str, bytes]) -> Path:
    """Build a read-only ISO image with Joliet + RockRidge long filenames via `xorriso` (or pure-Python fallback)."""
    iso_p = Path(iso_path)
    iso_p.parent.mkdir(parents=True, exist_ok=True)
    if iso_p.exists():
        iso_p.unlink()

    clean_files: dict[str, bytes] = {}
    for raw_name, payload in files.items():
        clean_files[_clean_iso_relpath(str(raw_name))] = bytes(payload)

    xorriso_bin = shutil.which("xorriso")
    alt_mkisofs = shutil.which("genisoimage") or shutil.which("mkisofs")
    if xorriso_bin or alt_mkisofs:
        shm_path = Path("/dev/shm")
        tmp_base = str(shm_path) if (shm_path.is_dir() and os.access(shm_path, os.W_OK | os.X_OK)) else None
        with tempfile.TemporaryDirectory(prefix="dfir_stage_iso_", dir=tmp_base) as tmp_dir:
            stage_root = Path(tmp_dir)
            os.chmod(stage_root, 0o700)
            sensitive_paths: list[tuple[Path, int]] = []
            try:
                for fname, payload in clean_files.items():
                    fpath = stage_root / fname
                    fpath.parent.mkdir(parents=True, exist_ok=True)
                    fpath.write_bytes(payload)
                    if fname == "payload.bin" or fname.startswith("batch_payloads/"):
                        os.chmod(fpath, 0o400)
                        sensitive_paths.append((fpath, len(payload)))
                if xorriso_bin:
                    cmd = [
                        xorriso_bin,
                        "-as",
                        "mkisofs",
                        "-J",
                        "-R",
                        "-V",
                        volume_label,
                        "-o",
                        str(iso_p),
                        str(stage_root),
                    ]
                else:
                    cmd = [
                        str(alt_mkisofs),
                        "-J",
                        "-R",
                        "-V",
                        volume_label,
                        "-o",
                        str(iso_p),
                        str(stage_root),
                    ]
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            finally:
                for spath, slen in sensitive_paths:
                    if spath.exists():
                        try:
                            os.chmod(spath, 0o600)
                            spath.write_bytes(b"\x00" * min(slen, 4096))
                            spath.unlink()
                        except Exception:
                            pass
        os.chmod(iso_p, 0o644)
        return iso_p

    root_only = {k: v for k, v in clean_files.items() if "/" not in k}
    iso_p.write_bytes(_build_minimal_iso9660(volume_label, root_only))
    os.chmod(iso_p, 0o644)
    return iso_p


def _write_cdrom_xml(xml_path: Path, iso_path: Path) -> None:
    xml_path.write_text(
        f"""<disk type='file' device='cdrom'>
  <driver name='qemu' type='raw'/>
  <source file='{iso_path.resolve()}'/>
  <target dev='sdc' bus='sata'/>
  <readonly/>
</disk>
""",
        encoding="utf-8",
    )


def build_stage_bundle(
    spec: StageRunSpec,
    out_dir: str | Path,
    sample_vault_file: str | Path | None = None,
    benign_script_text: str | None = None,
    extra_iso_files: Mapping[str, bytes] | None = None,
    archive_password: str | bytes | None = "infected",
    benign_pools_root: str | Path | None = None,
    run_seed: int | None = None,
    require_real_pools: bool = False,
) -> dict[str, Path]:
    """Validate `spec`, decrypt vault sample into RAM (if malware run), verify SHA-256, and build `DFIR_STAGE` ISO."""
    if str(spec.stratum).strip().lower() == "dormant_batch":
        raise PilotStagingError("Use build_dormant_batch_bundle(...) for dormant_batch specs")

    validate_stage_run_spec(spec)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    manifest_dict: dict[str, Any] = {
        **asdict(spec),
        "generated_at_utc": utc_now_iso(),
        "staging_transport": "readonly_iso9660_cdrom",
        "live_ssh_used": False,
        "qemu_guest_agent_used": False,
    }

    iso_files: dict[str, bytes] = {}
    if spec.stratum in ("dormant", "executed"):
        if sample_vault_file is None:
            raise PilotStagingError(f"sample_vault_file is required for {spec.stratum!r} staging")
        vpath = Path(sample_vault_file)
        payload_bytes = read_vault_payload_in_memory(vpath, password=archive_password)
        actual_sha = hashlib.sha256(payload_bytes).hexdigest().lower()
        if actual_sha != str(spec.sample_sha256).lower():
            raise PilotStagingError(
                f"Vault sample SHA-256 preflight mismatch: {actual_sha} != {spec.sample_sha256}"
            )
        iso_files["payload.bin"] = payload_bytes

    benign_manifest_path: Path | None = None
    if benign_script_text is None:
        ben_bundle = generate_benign_workload_bundle(
            run_id=spec.run_id,
            split_pool=spec.split_pool,
            benign_profile_id=spec.benign_profile_id,
            run_seed=run_seed,
            benign_pools_root=benign_pools_root,
            require_real_pools=require_real_pools,
        )
        eff_benign_text = ben_bundle["ps1_text"]
        for bname, bbytes in ben_bundle["extra_iso_files"].items():
            iso_files[str(bname)] = bytes(bbytes)
        benign_manifest_path = out_path / "benign_manifest.json"
        benign_manifest_path.write_text(
            json.dumps(ben_bundle["benign_manifest"], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        eff_benign_text = str(benign_script_text)

    manifest_bytes = json.dumps(manifest_dict, indent=2, sort_keys=True).encode("utf-8")
    bootstrapper_bytes = generate_guest_bootstrapper_ps1().encode("utf-8")
    benign_bytes = _inject_isolated_net_preamble(eff_benign_text).encode("utf-8")

    iso_files["run_manifest.json"] = manifest_bytes
    iso_files["Invoke-StagePayload.ps1"] = bootstrapper_bytes
    iso_files["benign_workload.ps1"] = benign_bytes
    if extra_iso_files:
        for ename, epayload in extra_iso_files.items():
            iso_files[str(ename)] = bytes(epayload)

    manifest_path = out_path / "run_manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    bootstrap_path = out_path / "Invoke-StagePayload.ps1"
    bootstrap_path.write_bytes(bootstrapper_bytes)
    benign_path = out_path / "benign_workload.ps1"
    benign_path.write_bytes(benign_bytes)

    iso_path = out_path / f"run_stage_{spec.run_id}.iso"
    build_stage_iso(iso_path, "DFIR_STAGE", iso_files)

    xml_path = out_path / "cdrom_device.xml"
    _write_cdrom_xml(xml_path, iso_path)
    out = {
        "manifest": manifest_path,
        "bootstrapper": bootstrap_path,
        "benign_workload": benign_path,
        "iso": iso_path,
        "cdrom_xml": xml_path,
    }
    if benign_manifest_path is not None:
        out["benign_manifest"] = benign_manifest_path
    return out


_DORMANT_BATCH_PS1_LOOP = r"""
# Stage dev-only dormant batch payloads (NEVER executes any staged binary; compatible with baked Invoke-StagePayload.ps1)
$maxBatch = __DORMANT_BATCH_MAX__
$batchVol = Get-Volume | Where-Object { $_.FileSystemLabel -eq "DFIR_STAGE" -and $_.DriveLetter } | Select-Object -First 1
if ($batchVol) {
    $bStageRoot = "$($batchVol.DriveLetter):\"
    $bManifestPath = Join-Path $bStageRoot "run_manifest.json"
    if (Test-Path -LiteralPath $bManifestPath) {
        $bMan = Get-Content -LiteralPath $bManifestPath -Raw | ConvertFrom-Json
        if ($bMan.stratum -eq "dormant_batch" -and $bMan.batch_samples) {
            $batchItems = @($bMan.batch_samples)
            if ($batchItems.Count -gt $maxBatch) {
                throw "dormant_batch sample count ($($batchItems.Count)) exceeds DORMANT_BATCH_MAX ($maxBatch)"
            }
            foreach ($bs in $batchItems) {
                $srcRel = ([string]$bs.iso_rel_path).Replace("/", "\")
                $srcFile = Join-Path $bStageRoot $srcRel
                $dstFile = [string]$bs.staging_target_path
                $dstDir = Split-Path -Parent $dstFile
                if (-not (Test-Path -LiteralPath $dstDir)) {
                    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
                }
                Copy-Item -LiteralPath $srcFile -Destination $dstFile -Force
                $actual = (Get-FileHash -LiteralPath $dstFile -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($actual -ne ([string]$bs.sample_sha256).ToLowerInvariant()) {
                    throw "SHA-256 mismatch on dormant_batch sample: $actual != $($bs.sample_sha256)"
                }
            }
        }
    }
}
""".replace("__DORMANT_BATCH_MAX__", str(DORMANT_BATCH_MAX))


def build_dormant_batch_bundle(
    spec: StageRunSpec,
    out_dir: str | Path,
    sample_vault_files: Mapping[str, str | Path] | Sequence[str | Path],
    benign_script_text: str | None = None,
    extra_iso_files: Mapping[str, bytes] | None = None,
    archive_password: str | bytes | None = "infected",
    benign_pools_root: str | Path | None = None,
    run_seed: int | None = None,
    require_real_pools: bool = False,
) -> dict[str, Path]:
    """Build a zero-rebake dev-only `dormant_batch` ISO staging up to 16 dormant samples (`DORMANT_BATCH_MAX`) inside `benign_workload.ps1`.

    Hard-refuses `split_pool != "dev"` so blind-test dormant runs remain strictly 1 sample per boot.
    """
    validate_stage_run_spec(spec)
    if str(spec.stratum).strip().lower() != "dormant_batch":
        raise PilotStagingError(f"build_dormant_batch_bundle requires stratum='dormant_batch', got {spec.stratum!r}")

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    items = list(spec.batch_samples)

    if isinstance(sample_vault_files, Mapping):
        vault_by_sha = {str(k).lower(): Path(v) for k, v in sample_vault_files.items()}
        resolved_vaults = [vault_by_sha.get(str(it["sample_sha256"]).lower()) for it in items]
    else:
        if len(sample_vault_files) != len(items):
            raise PilotStagingError(
                f"sample_vault_files count ({len(sample_vault_files)}) != batch_samples count ({len(items)})"
            )
        resolved_vaults = [Path(v) for v in sample_vault_files]

    iso_files: dict[str, bytes] = {}
    batch_manifest_entries: list[dict[str, Any]] = []
    for idx, (item, vpath) in enumerate(zip(items, resolved_vaults)):
        if vpath is None:
            raise PilotStagingError(f"Missing vault archive for dormant_batch sample {item['sample_sha256']}")
        sha = str(item["sample_sha256"]).lower()
        payload_bytes = read_vault_payload_in_memory(vpath, password=archive_password)
        actual_sha = hashlib.sha256(payload_bytes).hexdigest().lower()
        if actual_sha != sha:
            raise PilotStagingError(f"Vault SHA-256 mismatch for {sha}: got {actual_sha}")
        iso_rel = f"batch_payloads/sample_{idx:02d}.bin"
        iso_files[iso_rel] = payload_bytes
        batch_manifest_entries.append({
            "iso_rel_path": iso_rel,
            "staging_target_path": str(item["staging_target_path"]),
            "sample_sha256": sha,
            "sample_family": item.get("sample_family"),
            "sample_category": item.get("sample_category"),
            "pair_group_id": str(item["pair_group_id"]),
            "packer_cluster": item.get("packer_cluster"),
        })

    benign_manifest_path: Path | None = None
    if benign_script_text is None:
        ben_bundle = generate_benign_workload_bundle(
            run_id=spec.run_id,
            split_pool="dev",
            benign_profile_id=spec.benign_profile_id,
            run_seed=run_seed,
            benign_pools_root=benign_pools_root,
            require_real_pools=require_real_pools,
        )
        eff_benign_text = ben_bundle["ps1_text"]
        for bname, bbytes in ben_bundle["extra_iso_files"].items():
            iso_files[str(bname)] = bytes(bbytes)
        benign_manifest_path = out_path / "benign_manifest.json"
        benign_manifest_path.write_text(
            json.dumps(ben_bundle["benign_manifest"], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        eff_benign_text = str(benign_script_text)

    combined_ps1 = _inject_isolated_net_preamble(eff_benign_text) + "\n" + _DORMANT_BATCH_PS1_LOOP
    manifest_dict: dict[str, Any] = {
        **asdict(spec),
        "stratum": "dormant_batch",
        "execute_payload": False,
        "batch_samples": batch_manifest_entries,
        "generated_at_utc": utc_now_iso(),
        "staging_transport": "readonly_iso9660_cdrom",
        "live_ssh_used": False,
        "qemu_guest_agent_used": False,
    }
    manifest_bytes = json.dumps(manifest_dict, indent=2, sort_keys=True).encode("utf-8")
    bootstrapper_bytes = generate_guest_bootstrapper_ps1().encode("utf-8")
    benign_bytes = combined_ps1.encode("utf-8")

    iso_files["run_manifest.json"] = manifest_bytes
    iso_files["Invoke-StagePayload.ps1"] = bootstrapper_bytes
    iso_files["benign_workload.ps1"] = benign_bytes
    if extra_iso_files:
        for ename, epayload in extra_iso_files.items():
            iso_files[str(ename)] = bytes(epayload)

    manifest_path = out_path / "run_manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    bootstrap_path = out_path / "Invoke-StagePayload.ps1"
    bootstrap_path.write_bytes(bootstrapper_bytes)
    benign_path = out_path / "benign_workload.ps1"
    benign_path.write_bytes(benign_bytes)

    iso_path = out_path / f"run_stage_{spec.run_id}.iso"
    build_stage_iso(iso_path, "DFIR_STAGE", iso_files)

    xml_path = out_path / "cdrom_device.xml"
    _write_cdrom_xml(xml_path, iso_path)
    out = {
        "manifest": manifest_path,
        "bootstrapper": bootstrap_path,
        "benign_workload": benign_path,
        "iso": iso_path,
        "cdrom_xml": xml_path,
    }
    if benign_manifest_path is not None:
        out["benign_manifest"] = benign_manifest_path
    return out


def build_clean_parity_stage_iso(
    out_dir: str | Path,
    collector_ps1_path: str | Path | None = None,
    guest_out_dir: str = r"C:\collector_out_parity",
    run_id: str = "clean_parity_test",
    dwell_seconds: int = 30,
) -> dict[str, Path]:
    """Build a zero-SSH read-only `DFIR_STAGE` ISO that runs `Collect-Artifacts.ps1` inside the clean guest."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    coll_path = Path(collector_ps1_path) if collector_ps1_path is not None else (repo_root / "collector" / "Collect-Artifacts.ps1")
    if not coll_path.exists():
        raise FileNotFoundError(f"Collect-Artifacts.ps1 not found at {coll_path}")

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    collector_bytes = coll_path.read_bytes()

    parity_workload_ps1 = f"""# Zero-SSH Clean-Image Parity Workload (Invokes v1 Collect-Artifacts.ps1 into {guest_out_dir})
param([string]$ProfileId = "clean_parity_v1_collector")
$ErrorActionPreference = "Stop"
$vol = Get-Volume | Where-Object {{ $_.FileSystemLabel -eq "DFIR_STAGE" -and $_.DriveLetter }} | Select-Object -First 1
$stageRoot = if ($vol) {{ "$($vol.DriveLetter):\\" }} else {{ $PSScriptRoot }}
$collectorScript = Join-Path $stageRoot "COLLECT.PS1"
$outDir = "{guest_out_dir}"
$logPath = Join-Path $outDir "parity_stdout.log"
if (-not (Test-Path -LiteralPath $outDir)) {{
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}}
$prevPref = $ErrorActionPreference
try {{
    $ErrorActionPreference = "Continue"
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $collectorScript -OutDir $outDir 2>&1
    $collExit = $LASTEXITCODE
    $output | Out-File -LiteralPath $logPath -Encoding utf8
    "COLLECT_EXIT_CODE=$collExit" | Out-File -LiteralPath $logPath -Append -Encoding utf8
    if ($collExit -ne 0) {{
        throw "Collect-Artifacts.ps1 exited with code $collExit"
    }}
    $artifactsJson = Join-Path $outDir "artifacts.json"
    if (-not (Test-Path -LiteralPath $artifactsJson)) {{
        throw "Expected collector output missing: $artifactsJson"
    }}
}} catch {{
    $_ | Out-String | Out-File -LiteralPath $logPath -Append -Encoding utf8
    throw
}} finally {{
    $ErrorActionPreference = $prevPref
    Write-VolumeCache -DriveLetter C -ErrorAction SilentlyContinue
}}
"""
    spec = StageRunSpec(
        run_id=run_id,
        stratum="control",
        benign_profile_id="clean_parity_v1_collector",
        dwell_seconds=dwell_seconds,
        execute_payload=False,
    )
    bundle = build_stage_bundle(
        spec=spec,
        out_dir=out_path,
        benign_script_text=parity_workload_ps1,
        extra_iso_files={"COLLECT.PS1": collector_bytes},
    )
    coll_copy = out_path / "COLLECT.PS1"
    coll_copy.write_bytes(collector_bytes)
    bundle["collector_ps1"] = coll_copy
    return bundle
