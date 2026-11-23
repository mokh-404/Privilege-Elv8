"""Unit tests for Step F pure user-space offline extractor, base-image cache, TaskCache decoder, and zero-SSH staging."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import struct
import subprocess
import uuid

import pandas as pd
import pytest

from src.data import features as F
from src.v2.offline_extractor import (
    GOLDEN_BASE_IMAGE_SHA256,
    MIB,
    _parse_task_xml,
    close_target_safely,
    compute_head_histogram,
    decode_taskcache_actions_blob,
    decompress_wof_stream,
    extract_from_fixture,
    load_base_image_cache,
    make_base_file_cache_key,
    normalize_volume_prefix,
    open_qcow2_target_readonly,
    save_base_image_cache,
    validate_extracted_record,
    verify_offline_signature,
    write_outputs,
)
from src.v2.pilot_staging import (
    PilotStagingError,
    StageRunSpec,
    build_stage_bundle,
    build_stage_iso,
    validate_stage_run_spec,
)


def test_leading_1mib_histogram_and_no_payload_guard(tmp_path):
    big = bytes(range(256)) * ((MIB // 256) + 4096)  # ~2 MiB
    hist = compute_head_histogram(big)
    assert len(hist) == 256
    assert sum(hist) == MIB

    with pytest.raises(ValueError, match="Forbidden raw payload"):
        validate_extracted_record({"artifact_type": "file", "artifact_key": "file|a|a", "payload_bytes": "abcd"})
    with pytest.raises(ValueError, match="Raw binary blob"):
        validate_extracted_record({"artifact_type": "file", "artifact_key": "file|a|a", "binary_col": b"\x00\x01"})
    with pytest.raises(ValueError, match="1 MiB cap"):
        validate_extracted_record({
            "artifact_type": "file", "artifact_key": "file|a|a",
            "file_head_histogram": [MIB + 1] + [0] * 255,
        })


def test_wof_uncompressed_fallback_and_volume_normalization():
    raw_chunk = b"MZ" + b"A" * 100
    assert decompress_wof_stream(raw_chunk, len(raw_chunk), algo=2) == raw_chunk
    assert normalize_volume_prefix(r"\VOLUME{01dd79ad-aea94ff5}\WINDOWS\SYSTEM32\NTDLL.DLL") == r"C:\WINDOWS\SYSTEM32\NTDLL.DLL"


def test_offline_signature_sip_and_catroot_mapping():
    assert F.signature_state(verify_offline_signature(r"C:\test\run.pf", b"abcd", 4)) == "na"
    assert F.signature_state(verify_offline_signature(r"C:\test\job.bat", b"echo hi", 7)) == "na"
    assert F.signature_state(verify_offline_signature(r"C:\test\zero.exe", b"", 0)) == "na"
    assert verify_offline_signature(r"C:\test\signed.ps1", b"# SIG # Begin signature block\n", 30) == "Valid"
    assert F.signature_state(verify_offline_signature(r"C:\test\unsigned.ps1", b"Get-Date\n", 9)) == "unsigned"


def test_task_xml_parser_utf8_and_utf16le_exec_and_comhandler():
    xml = """<?xml version="1.0" encoding="UTF-16"?>
    <Task version="1.2">
      <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
      <Actions><Exec><Command>%ProgramData%\\App\\run.exe</Command><Arguments>/silent</Arguments></Exec>
      <ComHandler><ClassId>{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}</ClassId></ComHandler></Actions>
    </Task>"""
    for payload in (xml, xml.encode("utf-16")):
        parsed = _parse_task_xml(payload)
        assert "MSFT_TaskLogonTrigger" in parsed["triggers"]
        assert parsed["exec_actions"][0]["command_expanded"] == r"C:\ProgramData\App\run.exe"
        assert parsed["com_handlers"] == ["{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"]
        assert "COM:{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}" in parsed["command_line"]


def test_decode_taskcache_actions_blob_exec_and_comhandler():
    ctx = "Author".encode("utf-16-le")
    cmd = r"%SystemRoot%\System32\schtasks.exe".encode("utf-16-le")
    args = "/Run /TN Test".encode("utf-16-le")
    wdir = r"C:\Windows\System32".encode("utf-16-le")
    blob_exec = (
        struct.pack("<HI", 3, len(ctx))
        + ctx
        + struct.pack("<HI", 0x6666, 0)
        + struct.pack("<I", len(cmd)) + cmd
        + struct.pack("<I", len(args)) + args
        + struct.pack("<I", len(wdir)) + wdir
        + struct.pack("<H", 0)
    )
    dec_exec = decode_taskcache_actions_blob(blob_exec)
    assert len(dec_exec["exec_actions"]) == 1
    assert dec_exec["exec_actions"][0]["command_expanded"] == r"C:\WINDOWS\System32\schtasks.exe"
    assert dec_exec["exec_actions"][0]["arguments_raw"] == "/Run /TN Test"

    g_uuid = uuid.UUID("{429bc048-379e-45e0-80e4-eb1977941b5c}")
    data_u16 = "/RuntimeWide".encode("utf-16-le")
    for magic in (0x5555, 0x7777):
        blob_com = (
            struct.pack("<HI", 3, len(ctx))
            + ctx
            + struct.pack("<HI", magic, 0)
            + g_uuid.bytes_le
            + struct.pack("<I", len(data_u16))
            + data_u16
        )
        dec_com = decode_taskcache_actions_blob(blob_com)
        assert dec_com["com_handlers"] == ["{429bc048-379e-45e0-80e4-eb1977941b5c}"]
        assert "COM:{429BC048-379E-45E0-80E4-EB1977941B5C}" in dec_com["command_line"]


def test_base_image_cache_save_load_and_sha256_binding(tmp_path):
    cpath = tmp_path / "base_cache.json.gz"
    ckey = make_base_file_cache_key(1024, 3, 88232, 1772840911079985100)
    save_base_image_cache(
        cpath,
        base_image_sha256=GOLDEN_BASE_IMAGE_SHA256,
        catroot_digests=["abcd1234", "ef015678"],
        file_entries={
            ckey: {
                "path": r"C:\Windows\System32\svchost.exe",
                "file_size": 88232,
                "file_sha256": "11" * 32,
                "file_head_histogram": [100] + [0] * 255,
                "signature_status": "Valid",
                "wof_compressed": True,
            }
        },
    )
    loaded = load_base_image_cache(cpath, expected_base_sha256=GOLDEN_BASE_IMAGE_SHA256)
    assert loaded["catroot_digests_count"] == 2
    assert loaded["file_entries"][ckey]["wof_compressed"] is True

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_base_image_cache(cpath, expected_base_sha256="0" * 64)


def test_zero_ssh_pilot_staging_gate0_and_iso_bundle(tmp_path):
    # Control run succeeds without Gate 0
    ctrl_spec = StageRunSpec(
        run_id="pilot_ctrl_01",
        stratum="control",
        benign_profile_id="dev_office_01",
        dwell_seconds=60,
    )
    out = build_stage_bundle(ctrl_spec, tmp_path / "ctrl_bundle")
    assert out["iso"].exists() and out["manifest"].exists() and out["cdrom_xml"].exists()
    assert b"CD001" in out["iso"].read_bytes()
    assert "<readonly/>" in out["cdrom_xml"].read_text()

    # Malware dormant/executed run is blocked if Gate 0 is not signed off
    unsigned_spec = StageRunSpec(
        run_id="pilot_dorm_01",
        stratum="dormant",
        benign_profile_id="dev_office_01",
        staging_target_path=r"C:\Users\Public\Downloads\updater.exe",
        sample_sha256="a" * 64,
        pair_group_id="pair_01",
        execute_payload=False,
        gate0_signed_off=False,
        dedicated_host_user_verified=True,
    )
    with pytest.raises(PilotStagingError, match="Gate 0 .* is NOT signed off"):
        validate_stage_run_spec(unsigned_spec)

    # With Gate 0 signed off + dedicated host user verified + matching sample SHA-256, bundle builds cleanly
    dummy_sample = tmp_path / "sample.bin"
    dummy_bytes = b"MZ_SYNTHETIC_TEST_FIXTURE_ONLY"
    dummy_sample.write_bytes(dummy_bytes)
    import hashlib
    sha = hashlib.sha256(dummy_bytes).hexdigest()

    signed_dorm = StageRunSpec(
        run_id="pilot_dorm_01",
        stratum="dormant",
        benign_profile_id="dev_office_01",
        staging_target_path=r"C:\Users\Public\Downloads\updater.exe",
        sample_sha256=sha,
        sample_family="synth_family",
        pair_group_id="pair_01",
        execute_payload=False,
        gate0_signed_off=True,
        dedicated_host_user_verified=True,
    )
    dorm_out = build_stage_bundle(signed_dorm, tmp_path / "dorm_bundle", sample_vault_file=dummy_sample)
    man = json.loads(dorm_out["manifest"].read_text())
    assert man["live_ssh_used"] is False
    assert man["qemu_guest_agent_used"] is False
    assert man["execute_payload"] is False


def test_extract_from_fixture_outputs_and_refgraph_coverage(tmp_path):
    fixture = [
        {
            "artifact_type": "file",
            "artifact_key": r"file|c:\programdata\svc_helper.dll|svc_helper.dll",
            "name": "svc_helper.dll",
            "path": r"C:\ProgramData\svc_helper.dll",
            "sample_head_bytes_for_test": b"MZ" + b"\x90" * 510,
            "mft_record_number": 42,
            "mft_sequence_number": 3,
            "mft_in_use": True,
        },
        {
            "artifact_type": "run_key",
            "artifact_key": r"run_key|hku\run|updater",
            "name": "Updater",
            "path": r"C:\ProgramData\svc_helper.dll",
            "command_line": r"C:\ProgramData\svc_helper.dll",
            "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "registry_value": r"C:\ProgramData\svc_helper.dll",
        },
        {
            "artifact_type": "prefetch",
            "artifact_key": r"prefetch|c:\windows\prefetch\test.exe-12345678.pf|test.exe-12345678.pf",
            "name": "TEST.EXE-12345678.pf",
            "path": r"C:\Windows\Prefetch\TEST.EXE-12345678.pf",
            "pf_executable_name": "test.exe",
            "pf_scca_hash": "12345678",
            "pf_file_metrics": [{"file_path": r"C:\ProgramData\svc_helper.dll", "mft_index": 42, "mft_sequence": 3}],
        },
    ]
    recs, summary = extract_from_fixture(fixture, run_id="synth_01")
    assert summary["total_records"] == 3
    assert summary["refgraph_coverage"]["rows_with_resolved_outgoing"] == 2
    assert summary["refgraph_coverage"]["per_type"]["prefetch"]["resolved_rate_pct"] == 100.0

    paths = write_outputs(recs, summary, tmp_path / "out")
    assert paths["jsonl"].exists() and paths["parquet"].exists() and paths["manifest"].exists()
    df_pq = pd.read_parquet(paths["parquet"])
    assert len(df_pq) == 3
    loaded_manifest = json.loads(paths["manifest"].read_text())
    assert loaded_manifest["total_records"] == 3


def test_stage_iso_xorriso_preserves_long_filenames_and_fallback(tmp_path, monkeypatch):
    ctrl_spec = StageRunSpec(
        run_id="xorriso_long_names",
        stratum="control",
        benign_profile_id="dev_office_01",
        dwell_seconds=60,
    )
    out = build_stage_bundle(ctrl_spec, tmp_path / "bundle")
    iso_path = out["iso"]
    iso_bytes = iso_path.read_bytes()

    # Check Joliet Supplementary Volume Descriptor + UTF-16BE filenames + Volume Label
    assert b"\x02CD001\x01" in iso_bytes
    assert b"DFIR_STAGE" in iso_bytes
    assert "run_manifest.json".encode("utf-16-be") in iso_bytes
    assert "benign_workload.ps1".encode("utf-16-be") in iso_bytes

    xorriso_bin = shutil.which("xorriso")
    assert xorriso_bin is not None
    cp = subprocess.run([xorriso_bin, "-indev", str(iso_path), "-ls", "/"], capture_output=True, text=True, check=True)
    ls_out = cp.stdout
    for expected in ("run_manifest.json", "benign_workload.ps1", "Invoke-StagePayload.ps1"):
        assert expected in ls_out
    assert "RUN_MANI.JSO" not in ls_out
    assert "BENIGN_W.PS1" not in ls_out

    # Pure-Python fallback still works if host ISO tools are unavailable
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    fb_iso = build_stage_iso(tmp_path / "fallback.iso", "DFIR_STAGE", {"run_manifest.json": b"{}"})
    assert b"CD001" in fb_iso.read_bytes()


def test_open_qcow2_target_readonly_handles_absolute_backing_path(tmp_path):
    from dissect.target import Target  # type: ignore
    from dissect.target.exceptions import TargetError  # type: ignore

    qemu_img = shutil.which("qemu-img")
    assert qemu_img is not None

    base_dir = tmp_path / "base_store"
    overlay_dir = tmp_path / "overlay_store"
    base_dir.mkdir()
    overlay_dir.mkdir()

    raw_base = tmp_path / "raw_base.bin"
    marker = b"V2_ABS_BACKING_MARKER_123456"
    payload = bytearray(65536)
    payload[4096 : 4096 + len(marker)] = marker
    raw_base.write_bytes(payload)

    base_qcow2 = base_dir / "win11_base.qcow2"
    overlay_qcow2 = overlay_dir / "win11_overlay.qcow2"
    subprocess.run(
        [qemu_img, "convert", "-f", "raw", "-O", "qcow2", str(raw_base), str(base_qcow2)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base_qcow2.resolve()), str(overlay_qcow2)],
        check=True,
        capture_output=True,
        text=True,
    )

    with pytest.raises((TargetError, ValueError)):
        Target.open(str(overlay_qcow2), apply=False)

    tgt = open_qcow2_target_readonly(overlay_qcow2, apply=False)
    try:
        disk = tgt.disks[0]
        disk.seek(4096)
        assert disk.read(len(marker)) == marker
    finally:
        close_target_safely(tgt)
