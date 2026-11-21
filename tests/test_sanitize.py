"""FE-08 sanitization assertion and DS-10 runner-footprint tests."""
import pandas as pd
import pytest

from src.data import sanitize
from src.data.sanitize import SanitizationError, assert_clean, drop_runner_footprint, find_forbidden
from tests.fixtures import synthetic_rows

POSITIVE = ["AtomicRedTeam", "Atomic_Test_1", "Atomic Red Team", "T1053.005", "T1053_005", "ART", "ART_1",
            "Invoke-AtomicTest", "C:\\AtomicRedTeam\\atomics", "schtasks /tn T1053 /tr x", "atomic"]
NEGATIVE = ["Start Menu", "smart.exe", "Party", "atomicwallet", "SMART", "", "C:\\Windows\\System32\\cmd.exe",
            "Martha", "partial", "art", "KB5031356", "T10530", "XT1053"]


@pytest.mark.parametrize("s", POSITIVE)
def test_forbidden_positive(s):
    assert find_forbidden(s), s


@pytest.mark.parametrize("s", NEGATIVE)
def test_forbidden_negative(s):
    assert find_forbidden(s) == [], s


def test_non_string_is_clean():
    assert find_forbidden(None) == []
    assert find_forbidden(float("nan")) == []


def test_assert_clean_passes_on_clean_fixture(tmp_path):
    assert_clean(synthetic_rows(), report_path=tmp_path / "f.csv")
    assert not (tmp_path / "f.csv").exists()


def test_assert_clean_fails_and_reports(tmp_path):
    df = synthetic_rows()
    df.loc[1, "command_line"] = "powershell -File C:\\AtomicRedTeam\\x.ps1"
    df.loc[3, "task_name"] = "\\T1053_005_task"
    report = tmp_path / "sanitization_failures.csv"
    with pytest.raises(SanitizationError) as ei:
        assert_clean(df, report_path=report)
    out = pd.read_csv(report)
    assert set(out["artifact_key"]) == {df.loc[1, "artifact_key"], df.loc[3, "artifact_key"]}
    assert {"artifact_key", "field", "matched_text"} <= set(out.columns)
    assert set(out["field"]) == {"command_line", "task_name"}
    assert len(ei.value.failures) == 2


def test_assert_clean_does_not_modify_input(tmp_path):
    df = synthetic_rows()
    df.loc[0, "name"] = "ART_1"
    before = df.copy()
    with pytest.raises(SanitizationError):
        assert_clean(df, report_path=tmp_path / "f.csv")
    pd.testing.assert_frame_equal(df, before)   # assertion, not a scrubber


def test_drop_runner_footprint(tmp_path):
    df = pd.DataFrame([
        {"artifact_key": "a", "artifact_type": "process", "name": "sshd.exe", "path": "C:\\Windows\\x", "pid": 10},
        {"artifact_key": "b", "artifact_type": "process", "name": "powershell.exe", "path": "", "pid": 11},
        {"artifact_key": "c", "artifact_type": "process", "name": "powershell.exe", "path": "", "pid": 12},
        {"artifact_key": "d", "artifact_type": "file", "name": "out.json", "path": "C:\\collector_out\\out.json"},
        {"artifact_key": "e", "artifact_type": "file", "name": "x.exe", "path": "C:\\Users\\Public\\x.exe"},
    ])
    log = tmp_path / "drop.csv"
    kept, dropped = drop_runner_footprint(df, exclude_pids=[11], log_path=log)
    assert list(kept["artifact_key"]) == ["c", "e"]
    assert set(dropped["artifact_key"]) == {"a", "b", "d"}
    assert log.exists()
    assert len(pd.read_csv(log)) == 3


def test_patterns_are_the_spec_patterns():
    pats = [p.pattern for p in sanitize.config.FORBIDDEN_PATTERNS]
    assert len(pats) == 4
    assert pats[3] == r"(?<![A-Za-z])ART(?![A-Za-z])"
