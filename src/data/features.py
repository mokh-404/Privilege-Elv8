"""Deterministic feature extraction: Shannon entropy and the locked 20 features.

Input: a DataFrame of NORMALISED artifact rows (one row per artifact). Fields used
(missing values allowed; see docs/data_dictionary_features.md):

    artifact_type, artifact_key, name, path, command_line, registry_key, registry_value,
    task_name, service_name, parent_name, signature_status, attributes, file_size,
    file_head_histogram (256 byte counts over the first 1 MiB) or file_head_bytes,
    start_mode, task_triggers, created_utc, modified_utc

Output: META columns present in the input + the 20 FEATURES + ORACLE_FEATURES
(+ rule_hit_count if supplied) + label (if present). Oracle and rule columns are stored
but only exposed to models through clearly named ablations (src/config.py).

The FE-08 sanitization assertion runs BEFORE any string feature is computed.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable, Sequence

import numpy as np
import pandas as pd

from src import config
from src.data.sanitize import assert_clean

MIB = 1 << 20

# --------------------------------------------------------------------------------------
# Entropy (doc 10 "Calculation specs")
# --------------------------------------------------------------------------------------

def entropy_from_counts(counts: Iterable[int]) -> float:
    """Shannon entropy in bits from symbol counts. Empty/zero total -> 0.0 (never -0.0)."""
    counts = [int(c) for c in counts if c and int(c) > 0]
    total = sum(counts)
    if total == 0:
        return 0.0
    h = -sum((c / total) * math.log2(c / total) for c in counts)
    return max(0.0, h)


def shannon_entropy(x: str | bytes | bytearray | None) -> float:
    """H(x) over Unicode code points (str, no case folding) or byte values (bytes). H(empty)=0.0."""
    if x is None:
        return 0.0
    if isinstance(x, (bytes, bytearray)):
        return entropy_from_counts(Counter(x).values())
    if not isinstance(x, str):
        x = str(x)
    return entropy_from_counts(Counter(x).values())


def file_head_entropy(data: bytes | bytearray) -> float:
    """Entropy (bits per byte, 0..8) of the FIRST 1 MiB of a file's bytes."""
    return shannon_entropy(bytes(data[:MIB]))


def _histogram_entropy(hist: object) -> float:
    if isinstance(hist, str):
        hist = [int(v) for v in re.findall(r"\d+", hist)]
    hist = list(hist)  # type: ignore[arg-type]
    if len(hist) != 256:
        raise ValueError(f"file_head_histogram must have 256 counts, got {len(hist)}")
    return entropy_from_counts(hist)


# --------------------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------------------
_ENV_MAP = {
    "%systemroot%": r"c:\windows",
    "%windir%": r"c:\windows",
    "%systemdrive%": "c:",
    "%programfiles%": r"c:\program files",
    "%programfiles(x86)%": r"c:\program files (x86)",
    "%programw6432%": r"c:\program files",
    "%commonprogramfiles%": r"c:\program files\common files",
    "%programdata%": r"c:\programdata",
    "%allusersprofile%": r"c:\programdata",
    "%public%": r"c:\users\public",
    "%userprofile%": r"c:\users\_user_",
    "%appdata%": r"c:\users\_user_\appdata\roaming",
    "%localappdata%": r"c:\users\_user_\appdata\local",
    "%temp%": r"c:\users\_user_\appdata\local\temp",
    "%tmp%": r"c:\users\_user_\appdata\local\temp",
}
_EXEC_LIKE = r"exe|com|scr|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|dll|cpl|ocx|sys|msc|lnk|msi|py"
_EXE_PATH_RE = re.compile(rf"^(.+?\.(?:{_EXEC_LIKE}))(?=\s|,|$)", re.I)


def normalise_path(p: object) -> str:
    """Lower-case Windows path with env vars and NT prefixes expanded. '' if missing."""
    if p is None or (isinstance(p, float) and math.isnan(p)) or not isinstance(p, str):
        return ""
    s = p.strip().strip('"').strip().replace("/", "\\").lower()
    if not s:
        return ""
    for var, val in _ENV_MAP.items():
        s = s.replace(var, val)
    for pref in ("\\??\\", "\\\\?\\"):
        if s.startswith(pref):
            s = s[len(pref):]
    if s.startswith("\\systemroot\\"):
        s = "c:\\windows\\" + s[len("\\systemroot\\"):]
    elif s.startswith("systemroot\\"):
        s = "c:\\windows\\" + s[len("systemroot\\"):]
    elif s.startswith("system32\\"):
        s = "c:\\windows\\" + s
    return s


def extract_target_path(command_line: object) -> str:
    """Executable/target path at the start of a command line (normalised). '' if none."""
    if not isinstance(command_line, str) or not command_line.strip():
        return ""
    s = command_line.strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        return normalise_path(s[1:end] if end > 0 else s[1:])
    m = _EXE_PATH_RE.match(s)
    if m:
        return normalise_path(m.group(1))
    return normalise_path(s.split()[0])


def target_path(row: pd.Series | dict) -> str:
    """Primary filesystem path of an artifact: `path` if present, else parsed from `command_line`."""
    p = normalise_path(row.get("path"))
    return p if p else extract_target_path(row.get("command_line"))


def path_basename(p: str) -> str:
    return p.rstrip("\\").split("\\")[-1] if p else ""


def path_class(p: str) -> str:
    """system, program_files, user_writable, temp, appdata, other, na."""
    if not p:
        return "na"
    if (p.startswith("c:\\windows\\temp") or "\\appdata\\local\\temp" in p
            or "\\temp\\" in p or p.endswith("\\temp") or p.startswith("c:\\temp")):
        return "temp"
    if "\\appdata\\" in p or p.endswith("\\appdata"):
        return "appdata"
    if p.startswith("c:\\windows"):
        return "system"
    if p.startswith("c:\\program files"):
        return "program_files"
    if p.startswith(("c:\\users\\", "c:\\programdata", "c:\\perflogs", "c:\\$recycle.bin")):
        return "user_writable"
    return "other"


def path_depth(p: str) -> float:
    """Number of directories between the drive root and the final component. NaN if no path."""
    if not p:
        return float("nan")
    parts = [x for x in p.split("\\") if x]
    if parts and re.fullmatch(r"[a-z]:", parts[0]):
        parts = parts[1:]
    return float(max(0, len(parts) - 1))


_EXT_CLASSES = {
    "exe": {"exe", "com", "scr", "pif"},
    "dll": {"dll", "sys", "ocx", "cpl", "drv"},
    "script": {"ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "py", "sct"},
    "shortcut": {"lnk", "url"},
    "doc": {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "txt", "rtf", "csv", "odt",
            "htm", "html"},
}
_PREFETCH_RE = re.compile(r"^(.*)-[0-9a-f]{8}\.pf$", re.I)


def _extension(fname: str) -> str:
    fname = fname.lower()
    if "." not in fname.strip("."):
        return ""
    return fname.rsplit(".", 1)[-1]


def ext_class(fname: str) -> str:
    """exe, dll, script, shortcut, doc, other, na (from a file name)."""
    if not fname:
        return "na"
    ext = _extension(fname)
    if not ext:
        return "na"
    for cls, exts in _EXT_CLASSES.items():
        if ext in exts:
            return cls
    return "other"


def prefetch_exe_name(pf_name: str) -> str:
    """'NOTEPAD.EXE-D8414F97.pf' -> 'notepad.exe'."""
    m = _PREFETCH_RE.match(pf_name or "")
    return m.group(1).lower() if m else (pf_name or "").lower()


_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|zip|rar|mp3|mp4|csv|html?)"
    r"\.(exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|dll|cpl|msi)$",
    re.I,
)


def has_double_extension(fname: str) -> int:
    return int(bool(fname) and bool(_DOUBLE_EXT_RE.search(fname)))


# --------------------------------------------------------------------------------------
# Command-line helpers
# --------------------------------------------------------------------------------------
_TOKEN_SPLIT_RE = re.compile(r"[\s\"'&|;()^,<>]+")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://")
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])"
)
_LOLBINS = frozenset(config.LOLBIN_LIST)
_PS_RE = re.compile(r"(?i)(?:^|[\\\s\"'])(?:powershell|pwsh)(?:\.exe)?(?=[\s\"']|$)")


def _str(x: object) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return ""
    return x if isinstance(x, str) else str(x)


def cmd_tokens(cmd: str) -> list[str]:
    """Lower-case basenames of command-line tokens with .exe stripped."""
    out = []
    for tok in _TOKEN_SPLIT_RE.split(cmd.lower()):
        if not tok:
            continue
        if tok[0] in "/-" and "\\" not in tok and ":" not in tok and not tok.endswith(".exe"):
            continue
        base = tok.replace("/", "\\").rstrip("\\").split("\\")[-1]
        if base.endswith(".exe"):
            base = base[:-4]
        out.append(base)
    return out


def has_lolbin(cmd: str) -> int:
    return int(any(t in _LOLBINS for t in cmd_tokens(cmd))) if cmd else 0


def has_encoded_flag(cmd: str) -> int:
    """-enc / -EncodedCommand (any unambiguous prefix, incl. -e/-ec for PowerShell) / FromBase64String."""
    if not cmd:
        return 0
    low = cmd.lower()
    if "frombase64string" in low:
        return 1
    is_ps = bool(_PS_RE.search(cmd))
    for tok in re.split(r"\s+", low):
        if not tok or tok[0] not in "-/":
            continue
        t = tok.lstrip("-/")
        if len(t) >= 3 and "encodedcommand".startswith(t):   # -enc, -enco, ..., -encodedcommand
            return 1
        if is_ps and t in ("e", "ec", "en"):
            return 1
    return 0


def has_url_or_ip(*texts: str) -> int:
    for t in texts:
        if t and (_URL_RE.search(t) or _IPV4_RE.search(t)):
            return 1
    return 0


def nonalnum_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if not c.isalnum()) / len(s)


# --------------------------------------------------------------------------------------
# Categorical mappings
# --------------------------------------------------------------------------------------
_SIG_MAP = {
    "valid": "signed_trusted",
    "nottrusted": "signed_untrusted",
    # Get-AuthenticodeSignature returns UnknownError (with SignerCertificate = $null)
    # for unsupported/unreadable file types (.cmd, .bat, .hta, .pf, non-catalog .lnk,
    # 0-byte WindowsApps aliases, non-PE stubs) or collector exceptions — not untrusted signatures.
    "unknownerror": "na",
    "hashmismatch": "signed_untrusted",
    "notsigned": "unsigned",
}


def signature_state(status: object) -> str:
    """Map Get-AuthenticodeSignature Status to signed_trusted / signed_untrusted / unsigned / na."""
    s = _str(status).strip().lower().replace(" ", "").replace("_", "")
    return _SIG_MAP.get(s, "na")


_PARENT_CLASSES = [
    ("explorer", {"explorer.exe"}),
    ("services", {"services.exe"}),
    ("svchost", {"svchost.exe"}),
    ("cmd", {"cmd.exe"}),
    ("powershell", {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}),
    ("office", {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
                "mspub.exe", "visio.exe"}),
    ("browser", {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"}),
]


def parent_process_class(artifact_type: str, parent_name: object) -> str:
    if artifact_type != "process":
        return "na"
    pn = path_basename(normalise_path(parent_name))
    if not pn:
        return "na"
    for cls, names in _PARENT_CLASSES:
        if pn in names:
            return cls
    return "other"


def registry_location_class(key: object) -> str:
    k = _str(key).lower()
    if not k:
        return "na"
    if "\\currentversion\\runonce" in k:
        return "runonce"
    if "\\currentversion\\run" in k or "\\policies\\explorer\\run" in k:
        return "run"
    if re.search(r"\\(currentcontrolset|controlset\d{3})\\services\\", k):
        return "services"
    if "\\winlogon" in k:
        return "winlogon"
    if "\\image file execution options" in k:
        return "ifeo"
    return "other"


def has_hidden_attr(attributes: object) -> int:
    if attributes is None or (isinstance(attributes, float) and math.isnan(attributes)):
        return 0
    if isinstance(attributes, (int, np.integer)):
        return int(bool(int(attributes) & 0x2) or bool(int(attributes) & 0x4))
    if isinstance(attributes, (list, tuple, set)):
        attributes = ",".join(map(str, attributes))
    a = str(attributes).lower()
    return int("hidden" in a or "system" in a)


_AUTO_START_MODES = {"auto", "automatic", "boot", "system", "auto (delayed start)", "delayed-auto"}


def autostart_flag(row: pd.Series | dict, reg_class: str) -> int:
    at = row.get("artifact_type")
    if at == "startup":
        return 1
    if at in ("run_key", "registry") and reg_class in ("run", "runonce"):
        return 1
    if at == "service":
        return int(_str(row.get("start_mode")).strip().lower() in _AUTO_START_MODES)
    if at == "task":
        trig = _str(row.get("task_triggers")).lower()
        return int("logon" in trig or "boot" in trig)
    return 0


# --------------------------------------------------------------------------------------
# Row-level and frame-level feature computation
# --------------------------------------------------------------------------------------

def _file_entropy(row: pd.Series | dict) -> float:
    hist = row.get("file_head_histogram")
    if hist is not None and not (isinstance(hist, float) and math.isnan(hist)):
        return _histogram_entropy(hist)
    data = row.get("file_head_bytes")
    if isinstance(data, (bytes, bytearray)):
        return file_head_entropy(data)
    return float("nan")


def _file_size_log(row: pd.Series | dict) -> float:
    size = row.get("file_size")
    if size is None or (isinstance(size, float) and math.isnan(size)):
        return float("nan")
    return math.log10(1.0 + max(0.0, float(size)))


def row_features(row: pd.Series | dict) -> dict:
    """The 20 locked features for one (already sanitization-checked) normalised row."""
    at = _str(row.get("artifact_type")) or "na"
    tpath = target_path(row)
    name = _str(row.get("name"))
    cmd = _str(row.get("command_line"))
    reg_val = _str(row.get("registry_value"))
    reg_class = registry_location_class(row.get("registry_key"))

    fname = path_basename(tpath) or name
    if at == "prefetch":
        fname = prefetch_exe_name(path_basename(normalise_path(row.get("path"))) or name)
    # A bare file name with no directory (e.g. "powershell.exe -enc ...") carries no path
    # information: path_class = na and path_depth = NaN, but ext_class still uses the name.
    dir_path = tpath if "\\" in tpath else ""

    feats = {
        "artifact_type": at,
        "path_class": path_class(dir_path),
        "ext_class": ext_class(fname),
        "signature_state": signature_state(row.get("signature_status")),
        "parent_process_class": parent_process_class(at, row.get("parent_name")),
        "registry_location_class": reg_class,
        "path_depth": path_depth(dir_path),
        "name_length": float(len(name)),
        "name_entropy": shannon_entropy(name),
        "file_size_log": _file_size_log(row),
        "file_entropy": _file_entropy(row),
        "cmdline_length": float(len(cmd)),
        "cmdline_entropy": shannon_entropy(cmd),
        "cmdline_nonalnum_ratio": nonalnum_ratio(cmd),
        "has_double_extension": has_double_extension(fname),
        "has_encoded_flag": has_encoded_flag(cmd),
        "has_url_or_ip": has_url_or_ip(cmd, reg_val),
        "has_lolbin": has_lolbin(cmd),
        "has_hidden_attr": has_hidden_attr(row.get("attributes")),
        "autostart_flag": autostart_flag(row, reg_class),
    }
    assert list(feats) == config.FEATURES
    return feats


def _to_utc(x: object) -> pd.Timestamp | None:
    if x is None or (isinstance(x, float) and math.isnan(x)) or x == "":
        return None
    try:
        ts = pd.Timestamp(x)
    except (ValueError, TypeError):
        return None
    if ts is pd.NaT:
        return None
    return ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")


def oracle_features(
    row: pd.Series | dict,
    baseline_snapshot_utc: object = None,
    window: tuple[object, object] | None = None,
) -> dict:
    """ORACLE features (ablation only).

    file_age_minutes = (baseline_snapshot_utc - created_utc) in minutes: positive = existed before the
    baseline snapshot, negative = created after it. NaN if either time is missing.
    created_in_window = 1 if created_utc or modified_utc falls in [t_start, t_end], 0 otherwise,
    NaN if the row has no timestamp or no window is given.
    """
    created = _to_utc(row.get("created_utc"))
    modified = _to_utc(row.get("modified_utc"))
    base = _to_utc(baseline_snapshot_utc)
    age = (base - created).total_seconds() / 60.0 if (created is not None and base is not None) else float("nan")
    in_win = float("nan")
    if window is not None and (created is not None or modified is not None):
        t0, t1 = _to_utc(window[0]), _to_utc(window[1])
        if t0 is not None and t1 is not None:
            in_win = float(any(t is not None and t0 <= t <= t1 for t in (created, modified)))
    return {"file_age_minutes": age, "created_in_window": in_win}


def compute_features(
    df: pd.DataFrame,
    baseline_snapshot_utc: object = None,
    window: tuple[object, object] | None = None,
    rule_hit_count: Sequence[int] | pd.Series | None = None,
    sanitization_report: object = config.SANITIZATION_FAILURES_CSV,
) -> pd.DataFrame:
    """Sanitization assertion, then the 20 features + oracle (+ rule) columns for every row.

    Raises SanitizationError (and writes the report) if any feature-input string is dirty.
    """
    assert_clean(df, report_path=sanitization_report)   # FE-08: BEFORE any string feature

    feats = pd.DataFrame([row_features(r) for _, r in df.iterrows()], index=df.index, columns=config.FEATURES)
    oracle = pd.DataFrame(
        [oracle_features(r, baseline_snapshot_utc, window) for _, r in df.iterrows()],
        index=df.index, columns=config.ORACLE_FEATURES,
    )
    parts = [df[[c for c in config.META_COLUMNS if c in df.columns]], feats, oracle]
    if rule_hit_count is not None:
        parts.append(pd.DataFrame({"rule_hit_count": np.asarray(rule_hit_count, dtype=float)}, index=df.index))
    if config.LABEL_COL in df.columns:
        parts.append(df[[config.LABEL_COL]])
    out = pd.concat(parts, axis=1)
    for c in config.CATEGORICAL_FEATURES:
        out[c] = out[c].astype(str)
    for c in config.BINARY_FEATURES:
        out[c] = out[c].astype(int)
    return out
