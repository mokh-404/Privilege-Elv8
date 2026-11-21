"""15 deterministic forensic triage rules (RULE-001 through RULE-015).

Layer 1 of DFIR-Triage ("rules prove, the model ranks, the human decides").
Rules operate strictly on normalised artifact fields and NEVER read `label`,
`launcher`, or ground-truth `technique_id`.

`rule_hit_count` is excluded from main model training (`config.RULE_FEATURES`),
used only in the rule-hit ablation and `export_findings.py`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np
import pandas as pd

from src.data import features as F


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    technique_id: str
    category: str
    severity: str
    confidence: float
    description: str


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    technique_id: str
    category: str
    severity: str
    confidence: float
    reason: str


RULES: list[RuleSpec] = [
    RuleSpec("RULE-001", "T1547.001", "persistence", "high", 0.90,
             "Run/RunOnce key pointing to user-writable/temp path, script target, encoded PowerShell, or unsigned binary."),
    RuleSpec("RULE-002", "T1053.005", "persistence", "high", 0.90,
             "Scheduled task executing encoded PowerShell, a LOLBin, or a user-writable/temp target."),
    RuleSpec("RULE-003", "T1543.003", "persistence", "high", 0.88,
             "Service binary located in non-standard path or launching script interpreter."),
    RuleSpec("RULE-004", "T1547.001", "persistence", "high", 0.85,
             "Startup folder entry calling a LOLBin, script engine, or user-writable/temp target."),
    RuleSpec("RULE-005", "T1546.003", "persistence", "high", 0.92,
             "WMI event subscription (EventFilter/Consumer/Binding) outside built-in defaults."),
    RuleSpec("RULE-006", "T1218.011", "defense_evasion", "high", 0.88,
             "Signed-binary proxy execution pattern (rundll32/mshta/regsvr32/certutil)."),
    RuleSpec("RULE-007", "T1059.001", "execution", "high", 0.90,
             "PowerShell encoded command or hidden/bypass execution of user-writable/temp script."),
    RuleSpec("RULE-008", "T1574.001", "privilege_escalation", "medium", 0.80,
             "Unsigned executable or DLL in Temp, AppData, Users\\Public, or ProgramData."),
    RuleSpec("RULE-009", "T1036.005", "defense_evasion", "high", 0.88,
             "Hidden or System file attribute on binary or script in user-writable/temp path."),
    RuleSpec("RULE-010", "T1036.005", "defense_evasion", "high", 0.92,
             "Masqueraded Windows system binary name outside System32/SysWOW64, or double extension."),
    RuleSpec("RULE-011", "T1548.002", "privilege_escalation", "high", 0.95,
             "UAC bypass registry hijack key under ms-settings or mscfile shell\\open\\command."),
    RuleSpec("RULE-012", "T1112", "defense_evasion", "high", 0.92,
             "IFEO Debugger/MonitorProcess or non-standard Winlogon persistence registry key."),
    RuleSpec("RULE-013", "T1136.001", "persistence", "medium", 0.82,
             "Local account creation command or non-default enabled local Administrator account."),
    RuleSpec("RULE-014", "T1562.001", "defense_evasion", "high", 0.92,
             "Defense impairment registry indicator, Defender exclusion in writable path, or event-log clear."),
    RuleSpec("RULE-015", "T1552.001", "credential_access", "medium", 0.78,
             "Credential-in-files search command or staged discovery/collection script in writable path."),
]
RULES_BY_ID: dict[str, RuleSpec] = {r.rule_id: r for r in RULES}

_SUSPICIOUS_PATH_CLASSES = {"user_writable", "temp", "appdata"}
_SCRIPT_INTERP_TOKENS = {"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "python"}
_BUILTIN_WMI_NAMES = {"scm event log consumer", "bvtfilter", "tslogonfilter", "tslogonevents"}
_MASQ_SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "taskhostw.exe", "spoolsv.exe", "explorer.exe", "lsm.exe",
}
_PROXY_TOKENS = {"rundll32", "mshta", "regsvr32", "certutil"}
_SAFE_SYSTEM_DIRS = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
)
_KNOWN_DEFAULT_WINLOGON = {
    "shell": {"explorer.exe", "c:\\windows\\explorer.exe"},
    "userinit": {"c:\\windows\\system32\\userinit.exe,", "c:\\windows\\system32\\userinit.exe", "userinit.exe"},
}


def _s(val: Any) -> str:
    return F._str(val)


def _match(rule_id: str, reason: str) -> RuleMatch:
    spec = RULES_BY_ID[rule_id]
    return RuleMatch(
        rule_id=spec.rule_id,
        technique_id=spec.technique_id,
        category=spec.category,
        severity=spec.severity,
        confidence=spec.confidence,
        reason=reason,
    )


def _is_standard_system_binary(norm_path: str) -> bool:
    if not norm_path:
        return False
    if norm_path == "c:\\windows\\explorer.exe":
        return True
    return norm_path.startswith(_SAFE_SYSTEM_DIRS)


def _raw_dict(row: Mapping[str, Any]) -> dict:
    r = row.get("raw")
    return r if isinstance(r, dict) else {}


def evaluate_row(row: Mapping[str, Any]) -> list[RuleMatch]:
    """Evaluate all 15 deterministic rules on one normalised artifact row."""
    hits: list[RuleMatch] = []
    at = _s(row.get("artifact_type")).lower()
    name = _s(row.get("name"))
    name_low = name.lower()
    cmd = _s(row.get("command_line"))
    cmd_low = cmd.lower()
    reg_key = _s(row.get("registry_key"))
    reg_key_low = reg_key.lower()
    reg_val = _s(row.get("registry_value"))
    reg_val_low = reg_val.lower()
    tpath = F.target_path(row)
    pcls = F.path_class(tpath if "\\" in tpath else "")
    fname = F.path_basename(tpath) or name_low
    ecls = F.ext_class(fname)
    sig = F.signature_state(row.get("signature_status"))
    tokens = set(F.cmd_tokens(cmd))
    enc = F.has_encoded_flag(cmd)
    lolbin = F.has_lolbin(cmd)
    reg_cls = F.registry_location_class(reg_key)
    hidden = F.has_hidden_attr(row.get("attributes"))
    dbl_ext = F.has_double_extension(fname)
    raw = _raw_dict(row)

    # RULE-001: Run/RunOnce pointing to user-writable/temp or script/encoded/unsigned target
    if (at in ("run_key", "registry") and reg_cls in ("run", "runonce")):
        if (pcls in _SUSPICIOUS_PATH_CLASSES or ecls == "script" or enc
                or sig in ("unsigned", "signed_untrusted") or bool(tokens & _SCRIPT_INTERP_TOKENS)):
            hits.append(_match("RULE-001", f"Run/RunOnce '{name}' invokes {pcls}/{ecls} target"))

    # RULE-002: Scheduled task executing encoded PowerShell, LOLBin, or writable/temp script
    if at == "task":
        task_p = _s(row.get("task_name")).lower()
        is_non_ms = not task_p.startswith("\\microsoft\\")
        if is_non_ms and (enc or lolbin or pcls in _SUSPICIOUS_PATH_CLASSES
                          or (ecls == "script") or bool(tokens & _SCRIPT_INTERP_TOKENS)):
            hits.append(_match("RULE-002", f"Scheduled task '{name}' runs {cmd[:80]}"))

    # RULE-003: Service binary in non-standard path or launching script interpreter
    if at == "service":
        if (pcls in _SUSPICIOUS_PATH_CLASSES
                or bool(tokens & _SCRIPT_INTERP_TOKENS)
                or (tpath and not _is_standard_system_binary(tpath) and not tpath.startswith("c:\\program files")
                    and sig in ("unsigned", "signed_untrusted"))):
            hits.append(_match("RULE-003", f"Service '{name}' uses non-standard binary/command '{cmd[:80]}'"))

    # RULE-004: Startup folder entry calling LOLBin, script engine, or writable/temp target
    if at == "startup":
        sc_target = F.extract_target_path(cmd) or tpath
        sc_pcls = F.path_class(sc_target if "\\" in sc_target else "")
        sc_ecls = F.ext_class(F.path_basename(sc_target) or fname)
        if (lolbin or enc or sc_pcls in _SUSPICIOUS_PATH_CLASSES or sc_ecls == "script"
                or bool(tokens & _SCRIPT_INTERP_TOKENS) or sig in ("unsigned", "signed_untrusted")):
            hits.append(_match("RULE-004", f"Startup item '{name}' launches '{cmd[:80]}'"))

    # RULE-005: WMI event subscription persistence (non-builtin)
    if at == "wmi_subscription":
        if not any(b in name_low for b in _BUILTIN_WMI_NAMES):
            hits.append(_match("RULE-005", f"Non-default WMI subscription artifact '{name}'"))

    # RULE-006: Proxy execution via rundll32 / mshta / regsvr32 / certutil
    if tokens & _PROXY_TOKENS:
        suspicious_proxy = (
            ("certutil" in tokens and any(f in cmd_low for f in ("-decode", "/decode", "-urlcache", "/urlcache", "-encode", "/encode")))
            or ("mshta" in tokens and (".hta" in cmd_low or pcls in _SUSPICIOUS_PATH_CLASSES or "http" in cmd_low or "javascript:" in cmd_low or "vbscript:" in cmd_low))
            or ("regsvr32" in tokens and ("/i:" in cmd_low or "scrobj" in cmd_low or pcls in _SUSPICIOUS_PATH_CLASSES))
            or ("rundll32" in tokens and (pcls in _SUSPICIOUS_PATH_CLASSES or "temp\\" in cmd_low or "public\\" in cmd_low or "programdata\\" in cmd_low or "http" in cmd_low))
        )
        if suspicious_proxy:
            hits.append(_match("RULE-006", f"Proxy execution command '{cmd[:80]}'"))

    # RULE-007: PowerShell encoded command or hidden/bypass execution of writable/temp script
    if (("powershell" in tokens or "pwsh" in tokens)
            and (enc or (("-windowstyle hidden" in cmd_low or "-w hidden" in cmd_low or "-executionpolicy bypass" in cmd_low or "-ep bypass" in cmd_low)
                         and ("temp\\" in cmd_low or "public\\" in cmd_low or "programdata\\" in cmd_low or "appdata\\" in cmd_low)))):
        hits.append(_match("RULE-007", f"Encoded/hidden PowerShell invocation '{cmd[:80]}'"))

    # RULE-008: Unsigned EXE/DLL in Temp, AppData, Users\Public, or ProgramData
    if (ecls in ("exe", "dll") and sig in ("unsigned", "signed_untrusted")
            and (pcls in ("temp", "appdata") or tpath.startswith(("c:\\users\\public\\", "c:\\programdata\\")))):
        hits.append(_match("RULE-008", f"Unsigned {ecls} in writable path: {tpath}"))

    # RULE-009: Hidden/System attribute binary or script in user-writable/temp/appdata path
    if hidden and pcls in _SUSPICIOUS_PATH_CLASSES and name_low != "desktop.ini":
        hits.append(_match("RULE-009", f"Hidden/System attribute on '{tpath or name}'"))

    # RULE-010: Masqueraded Windows system binary outside System32/SysWOW64, or double extension
    if dbl_ext or (at in ("file", "process", "startup", "run_key", "service")
                   and fname in _MASQ_SYSTEM_NAMES and tpath and "\\" in tpath and not _is_standard_system_binary(tpath)):
        hits.append(_match("RULE-010", f"Masqueraded or double-extension binary '{tpath or fname}'"))

    # RULE-011: UAC bypass registry hijack key under ms-settings or mscfile
    if "\\software\\classes\\ms-settings\\shell\\open\\command" in reg_key_low or "\\software\\classes\\mscfile\\shell\\open\\command" in reg_key_low:
        hits.append(_match("RULE-011", f"UAC bypass registry key '{reg_key}' = '{reg_val}'"))

    # RULE-012: IFEO Debugger / MonitorProcess / GlobalFlag or non-standard Winlogon value
    if reg_cls == "ifeo" and name_low in ("debugger", "monitorprocess", "globalflag", "verifierdlls"):
        hits.append(_match("RULE-012", f"IFEO persistence value '{reg_key}\\{name}'"))
    elif reg_cls == "winlogon" and name_low in ("taskman", "shell", "userinit"):
        norm_rv = F.normalise_path(reg_val.strip())
        if name_low == "taskman" and reg_val.strip():
            hits.append(_match("RULE-012", f"Winlogon Taskman persistence '{reg_val}'"))
        elif name_low in ("shell", "userinit") and norm_rv and norm_rv not in _KNOWN_DEFAULT_WINLOGON[name_low]:
            hits.append(_match("RULE-012", f"Non-default Winlogon {name} '{reg_val}'"))

    # RULE-013: Local account creation command or non-default local Administrator account
    if (re.search(r"(?i)\bnet(?:\.exe)?\s+user\b.*\s/add\b", cmd_low)
            or "new-localuser" in cmd_low
            or (at == "account" and bool(raw.get("is_admin")) and raw.get("enabled", True)
                and name_low not in {"administrator"})):
        hits.append(_match("RULE-013", f"Local account creation or non-default local admin '{name or cmd[:60]}'"))

    # RULE-014: Defense impairment registry indicator, writable-path exclusion, or event-log clear
    if (("windows defender" in reg_key_low and name_low in ("disableantispyware", "disablerealtimemonitoring") and reg_val.strip() in ("1", "True", "true"))
            or ("windows defender\\exclusions\\paths" in reg_key_low and any(p in name_low or p in reg_val_low for p in ("\\temp", "\\public", "\\programdata", "\\users\\")))
            or re.search(r"(?i)\bwevtutil(?:\.exe)?\s+cl\b|\bclear-eventlog\b", cmd_low)):
        hits.append(_match("RULE-014", f"Defense impairment / log-clear indicator '{reg_key or cmd[:60]}'"))

    # RULE-015: Credential-in-files search or staged discovery/collection script in writable path
    if (re.search(r"(?i)\b(?:findstr|select-string)\b.*\b(?:password|token|secret|credential)\b", cmd_low)
            or (at == "file" and ecls == "script"
                and (pcls == "temp" or tpath.startswith(("c:\\users\\public\\", "c:\\programdata\\")))
                and not tpath.startswith("c:\\programdata\\microsoft\\"))):
        hits.append(_match("RULE-015", f"Staged script / credential search '{tpath or cmd[:60]}'"))

    return hits


def evaluate_dataframe(df: pd.DataFrame) -> tuple[list[list[RuleMatch]], np.ndarray]:
    """Evaluate all 15 deterministic rules over a normalised artifact DataFrame."""
    all_matches: list[list[RuleMatch]] = []
    counts = np.zeros(len(df), dtype=int)
    for idx, (_, row) in enumerate(df.iterrows()):
        m = evaluate_row(row)
        all_matches.append(m)
        counts[idx] = len(m)
    return all_matches, counts
