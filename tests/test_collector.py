"""Static & schema checks for collector/ (Prompt A).

Live execution is verified separately by the operator on the Windows 11 VM via
collector/Test-Collector.ps1 (no Windows host runtime assumptions here).
"""
import json
import re

from src import config


COLLECTOR_DIR = config.REPO_ROOT / "collector"
PS1 = COLLECTOR_DIR / "Collect-Artifacts.ps1"
SMOKE_PS1 = COLLECTOR_DIR / "Test-Collector.ps1"
SCHEMA_JSON = COLLECTOR_DIR / "manifest_schema.json"


def test_collector_files_exist_and_utf8():
    for p in (PS1, SMOKE_PS1, SCHEMA_JSON, COLLECTOR_DIR / "README.md"):
        assert p.exists(), p
        p.read_text(encoding="utf-8")


def test_manifest_schema_valid_json():
    schema = json.loads(SCHEMA_JSON.read_text(encoding="utf-8"))
    assert schema["properties"]["artifact_key_sep"]["const"] == config.ARTIFACT_KEY_SEP
    assert "script_sha256" in schema["required"]
    assert "outputs" in schema["required"]


def test_collector_is_read_only_on_host():
    src = PS1.read_text(encoding="utf-8")
    forbidden_host_mutations = [
        r"\bSet-ItemProperty\b",
        r"\bNew-ItemProperty\b",
        r"\bRemove-ItemProperty\b",
        r"\bRemove-Item\b",
        r"\bNew-Service\b",
        r"\bSet-Service\b",
        r"\bStart-Service\b",
        r"\bStop-Service\b",
        r"\bNew-ScheduledTask\b",
        r"\bRegister-ScheduledTask\b",
        r"\bNew-LocalUser\b",
        r"\breg(\.exe)?\s+(load|add|delete|import)\b",
        r"Win32_ShadowCopy.*Create\(",
    ]
    for pat in forbidden_host_mutations:
        assert not re.search(pat, src, re.I), f"Mutating pattern found in collector: {pat}"


def test_collector_covers_hku_sshd_amcache_and_pipe_sep():
    src = PS1.read_text(encoding="utf-8")
    assert "HKEY_USERS" in src
    assert "sshd.exe" in src
    assert "AppCompatCache" in src
    assert "locked_hive_no_vss" in src
    assert '$ArtifactKeySep = "|"' in src
    assert "record_sha256" in src
    assert "file_sha256" in src
    # No PowerShell 7-only ternary/null-coalescing operators (must stay PS 5.1 compatible)
    assert " ? " not in src
    assert " ?? " not in src


def test_collector_no_powershell_autovar_assignments():
    forbidden = {"pid", "host", "home", "input", "args", "true", "false", "null", "error", "psscriptroot", "pscommandpath"}
    for p in (PS1, SMOKE_PS1):
        src = p.read_text(encoding="utf-8")
        assigned = re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=", src)
        collisions = [v for v in assigned if v.lower() in forbidden]
        assert not collisions, f"{p.name} assigns PowerShell automatic variable(s): {collisions}"
