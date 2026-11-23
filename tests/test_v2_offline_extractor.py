"""Unit tests for Step F pure user-space offline extractor (no VM / no host mount)."""
from __future__ import annotations

import json
import struct

import pandas as pd
import pytest

from src.data import features as F
from src.v2.offline_extractor import (
    MIB,
    _parse_task_xml,
    compute_head_histogram,
    decompress_wof_stream,
    extract_from_fixture,
    normalize_volume_prefix,
    validate_extracted_record,
    verify_offline_signature,
    write_outputs,
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
    # Uncompressed chunk case: cdata length == expected size requires no offset table entries for 1 chunk
    assert decompress_wof_stream(raw_chunk, len(raw_chunk), algo=2) == raw_chunk
    assert normalize_volume_prefix(r"\VOLUME{01dd79ad-aea94ff5}\WINDOWS\SYSTEM32\NTDLL.DLL") == r"C:\WINDOWS\SYSTEM32\NTDLL.DLL"


def test_offline_signature_sip_and_catroot_mapping():
    assert F.signature_state(verify_offline_signature(r"C:\test\run.pf", b"abcd", 4)) == "na"
    assert F.signature_state(verify_offline_signature(r"C:\test\job.bat", b"echo hi", 7)) == "na"
    assert F.signature_state(verify_offline_signature(r"C:\test\zero.exe", b"", 0)) == "na"
    assert verify_offline_signature(r"C:\test\signed.ps1", b"# SIG # Begin signature block\n", 30) == "Valid"
    assert F.signature_state(verify_offline_signature(r"C:\test\unsigned.ps1", b"Get-Date\n", 9)) == "unsigned"


def test_task_xml_parser_exec_and_comhandler():
    xml = """<Task version="1.2">
      <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
      <Actions><Exec><Command>%ProgramData%\\App\\run.exe</Command><Arguments>/silent</Arguments></Exec>
      <ComHandler><ClassId>{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}</ClassId></ComHandler></Actions>
    </Task>"""
    parsed = _parse_task_xml(xml)
    assert "MSFT_TaskLogonTrigger" in parsed["triggers"]
    assert parsed["exec_actions"][0]["command_expanded"] == r"C:\ProgramData\App\run.exe"
    assert parsed["com_handlers"] == ["{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"]


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
