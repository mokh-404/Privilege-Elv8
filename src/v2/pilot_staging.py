"""Zero-SSH / Zero-Guest-Agent offline run staging builder for Stage A Pilot (`OD-V2-04`, `OD-V2-05`, `OD-V2-07`).

Because `01_firewall_win11_isolated.sh` drops all host-to-guest traffic on `virbr1` and
`02_domain_xml_hardening.md` removes `qemu-guest-agent`, SPICE clipboard/file transfer, and shared folders,
Stage A pilot runs stage their deterministic manifest, benign workload script, and (after Gate 0 sign-off)
paired `dormant` / `executed` payload via a per-run **read-only ISO-9660 virtual CD-ROM** (`DFIR_STAGE`)
attached before `virsh start win11`.

An in-guest pre-baked bootstrapper (`C:\\DFIR-Bootstrap\\Invoke-StagePayload.ps1`, registered under
`\\DFIR-StageRunner` during clean base image prep before sealing `chmod 0444`) reads the read-only
`DFIR_STAGE` volume at boot:
- `control` runs: executes only the deterministic benign workload (`execute_payload = False`).
- `dormant` runs (requires Gate 0 sign-off): copies the payload to `staging_target_path` (matching its
  paired `executed` run), verifies its SHA-256 on disk, and **never executes it**.
- `executed` runs (requires Gate 0 sign-off): copies the payload to the matching `staging_target_path`,
  verifies its SHA-256, emits a Sysmon/ETW root marker, and detonates it.
The host watchdog terminates the VM via `virsh destroy` after `dwell_seconds`, and `offline_extractor.py`
parses the closed overlay in user space (`--base-cache-path`). Zero SSH or `qemu-ga` channels ever open.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any

from src.utils.repro import utc_now_iso

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.I)
SUPERVISOR_APPROVAL_REF = (
    "Supervisor Marawan (AASTMT) written approval 2026-11-23 — "
    "'Research Approval Request: Controlled Malware Analysis for DFIR Triage' "
    "(Institutional Ethics Review: Not Required — Waived by Supervisor)"
)


class PilotStagingError(RuntimeError):
    """Raised when a Stage A pilot staging request violates Gate 0 or paired-stratum invariants."""


@dataclass(frozen=True)
class StageRunSpec:
    """Deterministic specification for one zero-SSH Stage A pilot VM run."""

    run_id: str
    stratum: str  # "control" | "dormant" | "executed"
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


def validate_stage_run_spec(spec: StageRunSpec) -> None:
    """Enforce Gate 0 (`OD-V2-07`) and paired `dormant`/`executed` staging invariants (`OD-V2-05`, `OD-V2-09`)."""
    st = str(spec.stratum).strip().lower()
    if st not in ("control", "dormant", "executed"):
        raise PilotStagingError(f"Invalid stratum {spec.stratum!r}; must be 'control', 'dormant', or 'executed'")
    if int(spec.dwell_seconds) < 10 or int(spec.dwell_seconds) > 1800:
        raise PilotStagingError(f"dwell_seconds must be in [10, 1800], got {spec.dwell_seconds}")

    if st == "control":
        if spec.execute_payload:
            raise PilotStagingError("control stratum must have execute_payload=False")
        if spec.sample_sha256 is not None:
            raise PilotStagingError("control stratum must not stage any malware sample_sha256")
        return

    # dormant or executed malware run -> enforce Gate 0 & Supervisor Marawan (AASTMT) conditions
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
    if not spec.sample_sha256 or not _SHA256_RE.match(str(spec.sample_sha256)):
        raise PilotStagingError(f"Valid 64-hex sample_sha256 required for {st!r} run, got {spec.sample_sha256!r}")
    if not spec.pair_group_id or not str(spec.pair_group_id).strip():
        raise PilotStagingError(f"pair_group_id required to pair dormant/executed runs (OD-V2-05/09)")
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

    # Layout:
    # Sectors 0..15: System Area (zeros)
    # Sector 16: Primary Volume Descriptor (PVD)
    # Sector 17: Volume Descriptor Set Terminator
    # Sector 18: Path Table (L-table)
    # Sector 19: Root Directory Record
    # Sector 20+: File data extents
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
        rec[18:25] = bytes([126, 11, 23, 0, 0, 0, 0])  # 2026-11-23 UTC
        rec[25] = flags
        rec[28:32] = _both16(1)
        rec[32] = id_len
        rec[33 : 33 + id_len] = ident
        return bytes(rec)

    # Root directory sector (Sector 19)
    root_dir = bytearray()
    root_dir.extend(_dir_record(b"\x00", 19, sector_size, 0x02))
    root_dir.extend(_dir_record(b"\x01", 19, sector_size, 0x02))
    for idx, name in enumerate(sorted_names):
        lba, dlen = file_sectors[name]
        # Store both an ISO 8.3 upper identifier and attach full name metadata in manifest
        stem = re.sub(r"[^A-Z0-9_]", "_", Path(name).stem.upper())[:8] or f"FILE{idx}"
        ext = re.sub(r"[^A-Z0-9_]", "", Path(name).suffix.upper().lstrip("."))[:3]
        iso_id = (f"{stem}.{ext};1" if ext else f"{stem}.;1").encode("ascii")
        root_dir.extend(_dir_record(iso_id, lba, dlen, 0x00))
    image[19 * sector_size : 19 * sector_size + len(root_dir)] = root_dir[:sector_size]

    # Path table (Sector 18)
    pt = bytearray(10)
    pt[0] = 1
    pt[1] = 0
    pt[2:6] = struct.pack("<I", 19)
    pt[6:8] = struct.pack("<H", 1)
    pt[8] = 0
    image[18 * sector_size : 18 * sector_size + len(pt)] = pt

    # Primary Volume Descriptor (Sector 16)
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

    # Terminator (Sector 17)
    term = bytearray(sector_size)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    image[17 * sector_size : 18 * sector_size] = term

    # File extents
    for name in sorted_names:
        lba, dlen = file_sectors[name]
        start = lba * sector_size
        image[start : start + dlen] = files[name]

    return bytes(image)


def build_stage_bundle(
    spec: StageRunSpec,
    out_dir: str | Path,
    sample_vault_file: str | Path | None = None,
    benign_script_text: str = "# Benign workload placeholder\n",
) -> dict[str, Path]:
    """Validate `spec`, verify vault sample SHA-256 (if malware run), and build read-only `DFIR_STAGE` ISO bundle."""
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
        if not vpath.exists():
            raise FileNotFoundError(f"Vault sample file not found: {vpath}")
        payload_bytes = vpath.read_bytes()
        actual_sha = hashlib.sha256(payload_bytes).hexdigest().lower()
        if actual_sha != str(spec.sample_sha256).lower():
            raise PilotStagingError(
                f"Vault sample SHA-256 preflight mismatch: {actual_sha} != {spec.sample_sha256}"
            )
        iso_files["payload.bin"] = payload_bytes

    manifest_bytes = json.dumps(manifest_dict, indent=2, sort_keys=True).encode("utf-8")
    bootstrapper_bytes = generate_guest_bootstrapper_ps1().encode("utf-8")
    benign_bytes = str(benign_script_text).encode("utf-8")

    iso_files["run_manifest.json"] = manifest_bytes
    iso_files["Invoke-StagePayload.ps1"] = bootstrapper_bytes
    iso_files["benign_workload.ps1"] = benign_bytes

    manifest_path = out_path / "run_manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    bootstrap_path = out_path / "Invoke-StagePayload.ps1"
    bootstrap_path.write_bytes(bootstrapper_bytes)
    benign_path = out_path / "benign_workload.ps1"
    benign_path.write_bytes(benign_bytes)

    iso_path = out_path / f"run_stage_{spec.run_id}.iso"
    iso_path.write_bytes(_build_minimal_iso9660("DFIR_STAGE", iso_files))

    xml_path = out_path / "cdrom_device.xml"
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
    return {
        "manifest": manifest_path,
        "bootstrapper": bootstrap_path,
        "benign_workload": benign_path,
        "iso": iso_path,
        "cdrom_xml": xml_path,
    }
