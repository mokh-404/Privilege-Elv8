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
    normalize_sysmon_evtx_record,
    normalize_volume_prefix,
    open_qcow2_target_readonly,
    patch_stale_large_pe_cache,
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
    read_vault_payload_in_memory,
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


def test_isolated_net_preamble_and_aes256_vault_in_memory(tmp_path):
    import hashlib
    import os
    import re

    # 1. Verify param(...) remains first statement when isolated static IP preamble is injected
    spec_ctrl = StageRunSpec(
        run_id="net_preamble_test",
        stratum="control",
        benign_profile_id="dev_office_01",
        dwell_seconds=45,
    )
    script_with_param = '# Header comment\nparam([string]$ProfileId = "x")\nWrite-Host $ProfileId\n'
    out_ctrl = build_stage_bundle(spec_ctrl, tmp_path / "ctrl_net", benign_script_text=script_with_param)
    rendered = out_ctrl["benign_workload"].read_text(encoding="utf-8")
    assert "192.168.150.50" in rendered and "192.168.150.10" in rendered
    assert re.match(r"^(?:\s|#[^\n]*\n)*param\(", rendered, flags=re.I) is not None
    assert rendered.index("param(") < rendered.index("netsh interface ip set address")

    # 2. Verify AES-256 encrypted zip decryption strictly in RAM via bsdtar & zero plaintext payload on host out_dir
    bsdtar_bin = shutil.which("bsdtar")
    xorriso_bin = shutil.which("xorriso")
    assert bsdtar_bin is not None and xorriso_bin is not None

    payload_bytes = b"MZ\x90\x00SYNTHETIC_AES256_VAULT_PAYLOAD"
    payload_sha = hashlib.sha256(payload_bytes).hexdigest()
    src_payload = tmp_path / "sample.exe"
    src_payload.write_bytes(payload_bytes)
    vault_zip = tmp_path / f"{payload_sha}.zip"
    subprocess.run(
        [
            bsdtar_bin,
            "--format",
            "zip",
            "--options",
            "zip:encryption=aes256",
            "--passphrase",
            "infected",
            "-cf",
            str(vault_zip),
            "-C",
            str(tmp_path),
            "sample.exe",
        ],
        check=True,
        capture_output=True,
    )
    os.chmod(vault_zip, 0o400)
    src_payload.unlink()

    assert read_vault_payload_in_memory(vault_zip, password="infected") == payload_bytes
    with pytest.raises(PilotStagingError):
        read_vault_payload_in_memory(vault_zip, password="wrong_password")

    exec_spec = StageRunSpec(
        run_id="pilot_aes_exec_01",
        stratum="executed",
        benign_profile_id="dev_office_01",
        staging_target_path=r"C:\Users\Public\Downloads\agent.exe",
        sample_sha256=payload_sha,
        sample_family="synth_fam",
        pair_group_id="pair_01",
        execute_payload=True,
        gate0_signed_off=True,
        dedicated_host_user_verified=True,
    )
    bundle_dir = tmp_path / "exec_bundle"
    out_exec = build_stage_bundle(exec_spec, bundle_dir, sample_vault_file=vault_zip, archive_password="infected")
    assert not (bundle_dir / "payload.bin").exists()

    verify_dir = tmp_path / "iso_read"
    verify_dir.mkdir()
    subprocess.run(
        [xorriso_bin, "-osirrox", "on", "-indev", str(out_exec["iso"]), "-extract", "/payload.bin", str(verify_dir / "payload.bin")],
        check=True,
        capture_output=True,
    )
    assert (verify_dir / "payload.bin").read_bytes() == payload_bytes


def test_patch_stale_large_pe_cache_and_sysmon_evtx_export(tmp_path, monkeypatch):
    import hashlib
    from src.v2 import offline_extractor as oe

    cache_path = tmp_path / "win11_base_cache.json.gz"
    stale_path = r"C:\Program Files\LargeVendor\OneDriveSetup.exe"
    small_path = r"C:\Users\Public\small_unsigned.exe"
    verified_large_path = r"C:\Program Files\SignedVendor\signed_large.exe"

    stale_key = make_base_file_cache_key(120, 99, 70 * MIB, 1772840911079985100)
    small_key = make_base_file_cache_key(121, 99, 16384, 1772840911079985100)
    signed_key = make_base_file_cache_key(122, 99, 90 * MIB, 1772840911079985100)

    save_base_image_cache(
        cache_path,
        base_image_sha256="b" * 64,
        catroot_digests={"cat123"},
        file_entries={
            stale_key: {
                "path": stale_path,
                "file_size": 70 * MIB,
                "signature_status": "NotSigned",
                "file_sha256": None,
                "file_head_histogram": [1] * 256,
                "wof_compressed": False,
            },
            small_key: {
                "path": small_path,
                "file_size": 16384,
                "signature_status": "NotSigned",
                "file_sha256": "c" * 64,
                "file_head_histogram": [0] * 256,
                "wof_compressed": False,
            },
            signed_key: {
                "path": verified_large_path,
                "file_size": 90 * MIB,
                "signature_status": "SignedEmbedded",
                "file_sha256": "d" * 64,
                "file_head_histogram": [0] * 256,
                "wof_compressed": False,
            },
        },
    )

    fake_large_bytes = b"MZ\x90\x00PATCHED_LARGE_PE_CONTENT_" * 4096

    class _FakeStat:
        def __init__(self, sz: int) -> None:
            self.st_size = sz

    class _FakePathObj:
        def __init__(self, norm: str) -> None:
            self._match = norm.lower() == stale_path.lower()

        def exists(self) -> bool:
            return self._match

        def is_dir(self) -> bool:
            return False

        def stat(self) -> _FakeStat:
            return _FakeStat(len(fake_large_bytes))

        def open(self, _mode: str):
            import io

            return io.BytesIO(fake_large_bytes)

    class _FakeFS:
        mounts: dict[str, object] = {}

        def path(self, norm: str) -> _FakePathObj:
            return _FakePathObj(norm)

    class _FakeTarget:
        fs = _FakeFS()

    monkeypatch.setattr(oe, "open_qcow2_target_readonly", lambda _p: _FakeTarget())
    monkeypatch.setattr(oe, "close_target_safely", lambda _t: None)
    monkeypatch.setattr(
        oe,
        "verify_offline_signature",
        lambda path, _b, _sz, _cats: "SignedCatalog" if "onedrivesetup.exe" in path.lower() else "NotSigned",
    )

    res = patch_stale_large_pe_cache(tmp_path / "base.qcow2", cache_path, expected_base_sha256="b" * 64)
    assert res["stale_candidates"] == 1
    assert res["patched_entries"] == 1

    reloaded = load_base_image_cache(cache_path, expected_base_sha256="b" * 64)
    assert reloaded["file_entries"][stale_key]["signature_status"] == "SignedCatalog"
    assert reloaded["file_entries"][stale_key]["file_sha256"] == hashlib.sha256(fake_large_bytes).hexdigest()
    assert reloaded["file_entries"][small_key]["signature_status"] == "NotSigned"
    assert reloaded["file_entries"][signed_key]["signature_status"] == "SignedEmbedded"

    # Second run sees 0 stale candidates
    res2 = patch_stale_large_pe_cache(tmp_path / "base.qcow2", cache_path, expected_base_sha256="b" * 64)
    assert res2["stale_candidates"] == 0 and res2["patched_entries"] == 0

    # Sysmon normalization & sysmon_events.jsonl export
    ev_proc = normalize_sysmon_evtx_record({
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "EventID": 1,
        "UtcTime": "2026-11-25 01:02:03.000",
        "ProcessGuid": "{mal-root}",
        "ParentProcessGuid": "{exp}",
        "ProcessId": "412",
        "ParentProcessId": "100",
        "Image": r"C:\Users\Public\sample.exe",
        "Hashes": "SHA256=" + "e" * 64,
    })
    assert ev_proc is not None and ev_proc["event_id"] == 1 and ev_proc["pid"] == 412
    assert normalize_sysmon_evtx_record({"Provider_Name": "Microsoft-Windows-Sysmon", "EventID": 999}) is None
    assert normalize_sysmon_evtx_record({"Provider_Name": "Microsoft-Windows-Kernel-General", "EventID": 1}) is None

    paths = write_outputs(
        [{
            "artifact_type": "file",
            "artifact_key": r"file|c:\users\public\sample.exe|sample.exe",
            "name": "sample.exe",
            "path": r"C:\Users\Public\sample.exe",
            "file_size": 1000,
        }],
        {"sysmon_evtx_present": True, "sysmon_events_count": 1, "sysmon_events": [ev_proc], "total_records": 1},
        tmp_path / "evtx_out",
    )
    assert "sysmon_jsonl" in paths and paths["sysmon_jsonl"].exists()
    ev_lines = [json.loads(ln) for ln in paths["sysmon_jsonl"].read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(ev_lines) == 1 and ev_lines[0]["process_guid"] == "{mal-root}"
    man = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    assert "sysmon_events" not in man  # Full event list stays in sysmon_events.jsonl, not bloated inside manifest
