"""Entropy edge cases (FE-09) and the 20-feature extractor on synthetic fixtures."""
import math
import os

import numpy as np
import pandas as pd
import pytest

from src import config
from src.data import features as F
from src.data.sanitize import SanitizationError
from tests.fixtures import synthetic_rows


# ---------------- entropy ----------------
def test_entropy_empty():
    assert F.shannon_entropy("") == 0.0
    assert math.copysign(1.0, F.shannon_entropy("")) == 1.0   # not -0.0
    assert F.shannon_entropy(b"") == 0.0
    assert F.shannon_entropy(None) == 0.0


def test_entropy_single_repeated_symbol():
    assert F.shannon_entropy("aaaa") == 0.0
    assert math.copysign(1.0, F.shannon_entropy("aaaa")) == 1.0
    assert F.shannon_entropy(b"\x00" * 1000) == 0.0


def test_entropy_256_distinct_bytes_is_8():
    assert F.shannon_entropy(bytes(range(256))) == pytest.approx(8.0, abs=1e-12)


def test_entropy_uniform_bytes_repeated():
    assert F.shannon_entropy(bytes(range(256)) * 10) == pytest.approx(8.0, abs=1e-12)


def test_entropy_random_bytes_close_to_8():
    rnd = np.random.default_rng(0).integers(0, 256, size=1 << 20, dtype=np.uint8).tobytes()
    assert 7.99 < F.shannon_entropy(rnd) <= 8.0


def test_entropy_two_symbols_and_case_sensitivity():
    assert F.shannon_entropy("ab") == pytest.approx(1.0)
    assert F.shannon_entropy("aA") == pytest.approx(1.0)   # no case folding
    assert F.shannon_entropy("abcd") == pytest.approx(2.0)


def test_entropy_unicode_code_points():
    assert F.shannon_entropy("éé") == 0.0
    assert F.shannon_entropy("éa") == pytest.approx(1.0)


def test_file_head_entropy_uses_first_mib_only():
    data = b"\x00" * F.MIB + bytes(range(256)) * 100
    assert F.file_head_entropy(data) == 0.0


def test_histogram_entropy_matches_bytes():
    data = os.urandom(5000)
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    assert F._histogram_entropy(hist) == pytest.approx(F.shannon_entropy(data))
    with pytest.raises(ValueError):
        F._histogram_entropy([1, 2, 3])


# ---------------- path helpers ----------------
@pytest.mark.parametrize("p,cls", [
    ("c:\\windows\\system32\\cmd.exe", "system"),
    ("c:\\program files\\7-zip\\7z.exe", "program_files"),
    ("c:\\program files (x86)\\x\\y.exe", "program_files"),
    ("c:\\users\\public\\x.exe", "user_writable"),
    ("c:\\programdata\\sync\\hlp.dll", "user_writable"),
    ("c:\\users\\bob\\appdata\\local\\temp\\a.ps1", "temp"),
    ("c:\\windows\\temp\\a.ps1", "temp"),
    ("c:\\users\\bob\\appdata\\roaming\\a.exe", "appdata"),
    ("d:\\tools\\a.exe", "other"),
    ("", "na"),
])
def test_path_class(p, cls):
    assert F.path_class(p) == cls


def test_normalise_and_extract_target_path():
    assert F.normalise_path("%SystemRoot%\\System32\\svchost.exe") == "c:\\windows\\system32\\svchost.exe"
    assert F.normalise_path("\\SystemRoot\\System32\\drivers\\x.sys") == "c:\\windows\\system32\\drivers\\x.sys"
    assert F.normalise_path("\\??\\C:\\Windows\\x.sys") == "c:\\windows\\x.sys"
    assert F.normalise_path("System32\\drivers\\y.sys") == "c:\\windows\\system32\\drivers\\y.sys"
    assert F.extract_target_path('"C:\\Program Files\\A B\\app.exe" --x') == "c:\\program files\\a b\\app.exe"
    assert F.extract_target_path("C:\\Program Files\\A B\\app.exe --x") == "c:\\program files\\a b\\app.exe"
    assert F.extract_target_path("rundll32.exe C:\\x.dll,Run") == "rundll32.exe"
    assert F.extract_target_path("") == ""
    assert F.extract_target_path(None) == ""


def test_path_depth():
    assert F.path_depth("c:\\windows\\system32\\cmd.exe") == 2
    assert F.path_depth("c:\\x.exe") == 0
    assert math.isnan(F.path_depth(""))


@pytest.mark.parametrize("n,cls", [
    ("a.exe", "exe"), ("a.DLL", "dll"), ("a.ps1", "script"), ("a.bat", "script"), ("a.lnk", "shortcut"),
    ("a.pdf", "doc"), ("a.pf", "other"), ("noext", "na"), ("", "na"), (".hidden", "na"),
])
def test_ext_class(n, cls):
    assert F.ext_class(n) == cls


def test_prefetch_exe_name():
    assert F.prefetch_exe_name("NOTEPAD.EXE-D8414F97.pf") == "notepad.exe"


@pytest.mark.parametrize("n,v", [
    ("report.pdf.exe", 1), ("invoice.docx.scr", 1), ("photo.jpg.lnk", 1),
    ("python3.12.exe", 0), ("setup.x64.exe", 0), ("report.pdf", 0), ("", 0),
])
def test_double_extension(n, v):
    assert F.has_double_extension(n) == v


# ---------------- command-line helpers ----------------
@pytest.mark.parametrize("cmd,v", [
    ("powershell.exe -enc SQBFAFgA", 1),
    ("powershell -EncodedCommand SQBFAFgA", 1),
    ("pwsh -e SQBFAFgA", 1),
    ("powershell.exe -ec SQBFAFgA", 1),
    ("powershell -c [Convert]::FromBase64String('x')", 1),
    ("xcopy /e a b", 0),
    ("powershell -ExecutionPolicy Bypass -File a.ps1", 0),
    ("", 0),
])
def test_encoded_flag(cmd, v):
    assert F.has_encoded_flag(cmd) == v


@pytest.mark.parametrize("cmd,v", [
    ("certutil -urlcache -f x", 1), ("C:\\Windows\\System32\\reg.exe add HKCU\\x", 1),
    ("cmd /c sc.exe create svc binPath= x", 1), ("\"C:\\Windows\\System32\\mshta.exe\" x.hta", 1),
    ("regedit.exe", 0), ("C:\\Program Files\\Notepad++\\notepad++.exe a.txt", 0), ("", 0),
    ("cmd /c schtasks /create /tn x", 1),
    ("backup.exe /sc daily /reg", 0),
])
def test_lolbin(cmd, v):
    assert F.has_lolbin(cmd) == v


def test_url_or_ip():
    assert F.has_url_or_ip("curl http://example.local/a") == 1
    assert F.has_url_or_ip("ping 192.168.1.10") == 1
    assert F.has_url_or_ip("ver 10.0.19041.1") == 0
    assert F.has_url_or_ip("", "x 10.1.2.3") == 1
    assert F.has_url_or_ip("", "") == 0


def test_nonalnum_ratio():
    assert F.nonalnum_ratio("") == 0.0
    assert F.nonalnum_ratio("ab") == 0.0
    assert F.nonalnum_ratio("a-b-") == 0.5


# ---------------- categorical mappings ----------------
def test_signature_state():
    assert F.signature_state("Valid") == "signed_trusted"
    assert F.signature_state("NotTrusted") == "signed_untrusted"
    assert F.signature_state("HashMismatch") == "signed_untrusted"
    assert F.signature_state("NotSigned") == "unsigned"
    assert F.signature_state("UnknownError") == "na"
    assert F.signature_state("unknownerror") == "na"
    assert F.signature_state("NotSupportedFileFormat") == "na"
    assert F.signature_state(None) == "na"


def test_parent_process_class():
    assert F.parent_process_class("process", "C:\\Windows\\explorer.exe") == "explorer"
    assert F.parent_process_class("process", "WINWORD.EXE") == "office"
    assert F.parent_process_class("process", "pwsh.exe") == "powershell"
    assert F.parent_process_class("process", "foo.exe") == "other"
    assert F.parent_process_class("process", None) == "na"
    assert F.parent_process_class("service", "services.exe") == "na"


@pytest.mark.parametrize("k,cls", [
    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "run"),
    ("HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "runonce"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\x", "services"),
    ("HKLM\\SYSTEM\\ControlSet001\\Services\\x", "services"),
    ("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "winlogon"),
    ("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\a.exe", "ifeo"),
    ("HKU\\S-1\\Software\\Classes\\ms-settings\\shell\\open\\command", "other"),
    (None, "na"),
])
def test_registry_location_class(k, cls):
    assert F.registry_location_class(k) == cls


def test_hidden_attr():
    assert F.has_hidden_attr("Hidden, Archive") == 1
    assert F.has_hidden_attr("System") == 1
    assert F.has_hidden_attr("Archive") == 0
    assert F.has_hidden_attr(2) == 1
    assert F.has_hidden_attr(32) == 0
    assert F.has_hidden_attr(None) == 0


# ---------------- frame-level ----------------
def test_compute_features_columns_and_values(tmp_path):
    df = synthetic_rows()
    out = F.compute_features(df, baseline_snapshot_utc="2026-11-21T00:00:00Z",
                             window=("2026-11-21T11:58:00Z", "2026-11-21T12:05:00Z"),
                             sanitization_report=tmp_path / "s.csv")
    expected = [c for c in config.META_COLUMNS if c in df.columns] + config.FEATURES + config.ORACLE_FEATURES + [config.LABEL_COL]
    assert list(out.columns) == expected
    assert len(out) == len(df)
    r = out.iloc[1]   # run key
    assert (r.artifact_type, r.registry_location_class, r.has_encoded_flag, r.autostart_flag) == ("run_key", "run", 1, 1)
    assert r.path_class == "na" and math.isnan(r.path_depth) and r.ext_class == "exe"   # bare name, no dir
    f = out.iloc[2]   # double-ext hidden file
    assert (f.path_class, f.ext_class, f.has_double_extension, f.has_hidden_attr, f.signature_state) == \
        ("user_writable", "exe", 1, 1, "unsigned")
    assert f.file_entropy == pytest.approx(8.0)
    assert f.file_size_log == pytest.approx(math.log10(1024))
    assert f.created_in_window == 1.0
    t = out.iloc[3]   # logon task
    assert (t.autostart_flag, t.path_class, t.ext_class) == (1, "program_files", "exe")
    p = out.iloc[4]   # rundll32 process
    assert (p.parent_process_class, p.has_lolbin, p.has_url_or_ip, p.path_class) == ("cmd", 1, 1, "system")
    assert p.created_in_window == 0.0 and p.file_age_minutes > 0
    pf = out.iloc[5]
    assert (pf.artifact_type, pf.ext_class, pf.path_class) == ("prefetch", "exe", "system")
    svc = out.iloc[0]
    assert (svc.autostart_flag, svc.registry_location_class, svc.signature_state) == (0, "services", "signed_trusted")
    assert math.isnan(svc.file_entropy)
    for c in config.CATEGORICAL_FEATURES:
        assert set(out[c]) <= set(config.CATEGORICAL_LEVELS[c]), c


def test_compute_features_is_deterministic(tmp_path):
    a = F.compute_features(synthetic_rows(), sanitization_report=tmp_path / "s.csv")
    b = F.compute_features(synthetic_rows(), sanitization_report=tmp_path / "s.csv")
    pd.testing.assert_frame_equal(a, b)


def test_compute_features_refuses_dirty_input(tmp_path):
    df = synthetic_rows()
    df.loc[2, "name"] = "Atomic_Test_1.exe"
    with pytest.raises(SanitizationError):
        F.compute_features(df, sanitization_report=tmp_path / "s.csv")
    assert (tmp_path / "s.csv").exists()


def test_rule_hit_count_column_optional(tmp_path):
    df = synthetic_rows()
    out = F.compute_features(df, rule_hit_count=[0] * len(df), sanitization_report=tmp_path / "s.csv")
    assert "rule_hit_count" in out.columns
    assert "rule_hit_count" not in config.FEATURES
