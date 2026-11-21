"""Central configuration: locked feature lists, seeds, paths, and constants.

The feature lists are LOCKED (docs/10_implementation_and_prompts.md section 2).
ORACLE_FEATURES, RULE_FEATURES, META_COLUMNS and LABEL_COL are never inputs to a
main (primary benchmark) model. They are only used by clearly named ablations.

A model score produced anywhere in this repository is a ranking signal (a lead),
never a verdict. Findings come only from deterministic rules (src/rules).
"""
from __future__ import annotations

import re
from pathlib import Path

# --------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
RAW_RUNS_DIR = DATA_DIR / "raw" / "runs"
INTERIM_DIR = DATA_DIR / "interim"
PROCESSED_DIR = DATA_DIR / "processed"
SPLITS_DIR = DATA_DIR / "splits"
EXTERNAL_DIR = DATA_DIR / "external"
CIC_MALMEM_CSV = EXTERNAL_DIR / "cic_malmem_2022" / "Obfuscated-MalMem2022.csv"

RESULTS_DIR = REPO_ROOT / "results"
TABLES_DIR = RESULTS_DIR / "tables"
FIGURES_DIR = RESULTS_DIR / "figures"
MODELS_DIR = RESULTS_DIR / "models"
LOGS_DIR = RESULTS_DIR / "logs"
SANITIZATION_FAILURES_CSV = LOGS_DIR / "sanitization_failures.csv"
RUNNER_FOOTPRINT_LOG_CSV = LOGS_DIR / "runner_footprint_dropped.csv"

LAB_DIR = REPO_ROOT / "lab_automation"
PROVENANCE_DIR = LAB_DIR / "provenance"
TECHNIQUES_YAML = LAB_DIR / "techniques.yaml"

# --------------------------------------------------------------------------------------
# Seeds (global SEED = 42 everywhere; separate draw seeds are logged in result metadata)
# --------------------------------------------------------------------------------------
SEED = 42
DEV_CV_SEEDS = [0, 1, 2]                 # repeated grouped CV on dev (doc 07 section 5)
HOLDOUT_TECHNIQUE_DRAW_SEED = 42         # Track A 5-technique holdout draw (proposed; operator confirms)
BOOTSTRAP_SEED = 42                      # run-level bootstrap on the frozen test set
TRACK_B_HOLDOUT_DRAW_SEED = 42           # Track B split-2 family draw
TRACK_B_KMEANS_SEED = 42                 # Track B benign k-means grouping
N_BOOTSTRAP = 1000

# --------------------------------------------------------------------------------------
# Locked 20-feature schema (doc 10 section 2) -- DO NOT EDIT without operator sign-off
# --------------------------------------------------------------------------------------
CATEGORICAL_FEATURES = [            # one-hot; every one has an "na" level
    "artifact_type",                # task, service, run_key, startup, prefetch, amcache, process, account (+ see ARTIFACT_TYPE_LEVELS)
    "path_class",                   # system, program_files, user_writable, temp, appdata, other, na
    "ext_class",                    # exe, dll, script, shortcut, doc, other, na
    "signature_state",              # signed_trusted, signed_untrusted, unsigned, na
    "parent_process_class",         # explorer, services, svchost, cmd, powershell, office, browser, other, na
    "registry_location_class",      # run, runonce, services, winlogon, ifeo, other, na
]
NUMERIC_FEATURES = [
    "path_depth",                   # int
    "name_length",                  # int
    "name_entropy",                 # float, bits per character
    "file_size_log",                # float, log10(1 + bytes); na for non-files
    "file_entropy",                 # float, bits per byte (0 to 8); na for non-files
    "cmdline_length",               # int; 0 if no command line
    "cmdline_entropy",              # float, bits per character
    "cmdline_nonalnum_ratio",       # float in [0,1]
]
BINARY_FEATURES = [
    "has_double_extension",         # e.g. report.pdf.exe
    "has_encoded_flag",             # -enc / -EncodedCommand / FromBase64String
    "has_url_or_ip",                # http(s):// or dotted IPv4 in command line or value
    "has_lolbin",                   # command line invokes a name from LOLBIN_LIST
    "has_hidden_attr",              # Hidden or System attribute on the file
    "autostart_flag",               # Run key, startup, auto service, logon/boot task
]
FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES + BINARY_FEATURES
assert len(FEATURES) == 20

# Never in the main model:
ORACLE_FEATURES = ["file_age_minutes", "created_in_window"]   # oracle ablation only
RULE_FEATURES = ["rule_hit_count"]                            # rule-hit ablation only
META_COLUMNS = ["run_id", "technique_id", "variant", "launcher", "artifact_key"]
LABEL_COL = "label"   # attacker_induced | benign_drift | baseline -> y = (label == "attacker_induced")
POSITIVE_LABEL = "attacker_induced"
BENIGN_LABELS = ["baseline", "benign_drift"]
LABEL_VALUES = [POSITIVE_LABEL] + BENIGN_LABELS
assert not set(FEATURES) & set(ORACLE_FEATURES + RULE_FEATURES + META_COLUMNS + [LABEL_COL])

FORBIDDEN_MODEL_INPUTS = frozenset(ORACLE_FEATURES + RULE_FEATURES + META_COLUMNS + [LABEL_COL])

# Categorical level sets. "na" is always a level. Core 8 levels come from doc 10;
# extra levels (file, shimcache, wmi_subscription, registry, other) were approved by the
# operator (docs/12_operator_decisions.md, Q-S1-2) to cover ShimCache, WMI subscriptions,
# UAC/IFEO keys and dropped files within the locked 20-feature schema.
ARTIFACT_TYPE_LEVELS = [
    "task", "service", "run_key", "startup", "prefetch", "amcache", "process", "account",
    "file", "shimcache", "wmi_subscription", "registry", "other", "na",
]
PATH_CLASS_LEVELS = ["system", "program_files", "user_writable", "temp", "appdata", "other", "na"]
EXT_CLASS_LEVELS = ["exe", "dll", "script", "shortcut", "doc", "other", "na"]
SIGNATURE_STATE_LEVELS = ["signed_trusted", "signed_untrusted", "unsigned", "na"]
PARENT_PROCESS_CLASS_LEVELS = [
    "explorer", "services", "svchost", "cmd", "powershell", "office", "browser", "other", "na",
]
REGISTRY_LOCATION_CLASS_LEVELS = ["run", "runonce", "services", "winlogon", "ifeo", "other", "na"]
CATEGORICAL_LEVELS = {
    "artifact_type": ARTIFACT_TYPE_LEVELS,
    "path_class": PATH_CLASS_LEVELS,
    "ext_class": EXT_CLASS_LEVELS,
    "signature_state": SIGNATURE_STATE_LEVELS,
    "parent_process_class": PARENT_PROCESS_CLASS_LEVELS,
    "registry_location_class": REGISTRY_LOCATION_CLASS_LEVELS,
}

# Feature groups for the "drop feature group" ablation (doc 07 section 6).
FEATURE_GROUPS = {
    "path": ["path_class", "path_depth", "ext_class", "has_double_extension", "name_length", "name_entropy"],
    "cmdline": ["cmdline_length", "cmdline_entropy", "cmdline_nonalnum_ratio", "has_encoded_flag",
                "has_url_or_ip", "has_lolbin", "parent_process_class"],
    "signature": ["signature_state", "file_size_log", "file_entropy", "has_hidden_attr"],
    "registry": ["registry_location_class", "autostart_flag"],
}

# LOLBIN_LIST (fixed; extend only before the test set is frozen). Matched as command-line tokens.
LOLBIN_LIST = [
    "certutil", "mshta", "regsvr32", "rundll32", "wmic", "bitsadmin", "cscript", "wscript",
    "msbuild", "installutil", "forfiles", "schtasks", "sc", "reg",
]

# --------------------------------------------------------------------------------------
# Normalised artifact row schema (input to sanitize.py / features.py / rules)
# --------------------------------------------------------------------------------------
# Each normalised row is one artifact. Field names below are produced by the collector ->
# normaliser step (Step 5/7). Missing values are None/NaN.
ARTIFACT_KEY_SEP = "|"   # canonical separator everywhere, incl. findings.json (Q-S1-1 resolved)

# Every string that feeds a feature (directly or via a class mapping). FE-08 assertion runs on all of them.
STRING_INPUT_FIELDS = [
    "name", "path", "command_line", "registry_key", "registry_value",
    "task_name", "service_name", "parent_name",
]

# --------------------------------------------------------------------------------------
# Forbidden-token patterns (FE-08, doc 10 section 2) -- assertion, never a scrubber
# --------------------------------------------------------------------------------------
FORBIDDEN_PATTERNS = [
    re.compile(r"(?<![A-Za-z])atomic(?:redteam|test|runner)?(?![A-Za-z])", re.I),
    re.compile(r"(?<![A-Za-z])invoke-atomic[A-Za-z-]*", re.I),
    re.compile(r"(?<![A-Za-z0-9])T1\d{3}(?:[._]\d{3})?(?![0-9])", re.I),   # T1053.005 and T1053_005
    re.compile(r"(?<![A-Za-z])ART(?![A-Za-z])"),                           # case-sensitive
]

# --------------------------------------------------------------------------------------
# Runner footprint exclusion (DS-10). Rows matching these are dropped BEFORE sanitization
# and logged to RUNNER_FOOTPRINT_LOG_CSV. Per-run PIDs (sshd.exe, launcher wrapper shells,
# collector tree) are read from the host-side provenance log at labeling time.
# --------------------------------------------------------------------------------------
RUNNER_EXCLUDE_PATHS = [
    # Lower-case path prefixes inside the guest (filled in Step 5/6 once the wrapper paths are fixed).
    r"c:\collector_out",
    r"c:\programdata\ssh",
]
RUNNER_EXCLUDE_PROCESS_NAMES = ["sshd.exe", "sshd-session.exe", "ssh-agent.exe"]
RUNNER_EXCLUDE_PIDS: list[int] = []   # static list is empty; per-run PIDs come from provenance

# --------------------------------------------------------------------------------------
# Track A split constants (doc 07 section 2)
# --------------------------------------------------------------------------------------
BENIGN_BUCKET_MOD = 100
BENIGN_TEST_BUCKET_MIN = 75         # bucket >= 75 -> test pool
N_DEV_FOLDS = 5                     # dev fold = bucket % 5
N_HOLDOUT_TECHNIQUES = 5
MIN_HOLDOUT_TACTICS = 4

# --------------------------------------------------------------------------------------
# Metrics (doc 07 section 4)
# --------------------------------------------------------------------------------------
K_VALUES = [10, 50, 100]
FIXED_RECALL = 0.9
TRACK_B_FPR_TARGETS = [0.01, 0.05]

# --------------------------------------------------------------------------------------
# Track B (CIC-MalMem-2022)
# --------------------------------------------------------------------------------------
CIC_EXPECTED_SHAPE = (58596, 57)
CIC_LABEL_COL = "Class"
CIC_CATEGORY_COL = "Category"
CIC_POSITIVE_CLASS = "Malware"
CIC_NEGATIVE_CLASS = "Benign"
CIC_N_FAMILIES = 15
CIC_CATEGORIES = ["Ransomware", "Spyware", "Trojan"]
TRACK_B_SPLIT1_TEST_SIZE = 0.20
TRACK_B_SPLIT1_TAG = "LEAKY: reproduction of published setup only"
TRACK_B_N_BENIGN_CLUSTERS = 50
TRACK_B_BENIGN_TEST_FRACTION = 0.20
TRACK_B_BENIGN_VAL_FRACTION = 0.10   # benign validation portion (thresholds + early stopping)
TRACK_B_CAVEAT = (
    "CAVEAT: benign false-positive rates are likely optimistic because SMOTE-synthesised benign "
    "rows cannot be fully separated between train and test (cluster grouping is an approximation)."
)

# --------------------------------------------------------------------------------------
# Default (untuned) hyperparameters. Track A tunes on dev folds only (<= 20 trials/arm).
# Track B uses these fixed values (no tuning on any test split).
# --------------------------------------------------------------------------------------
DEFAULT_PARAMS = {
    "rf": {"n_estimators": 300, "max_depth": None, "min_samples_leaf": 1},
    "xgb": {"n_estimators": 400, "learning_rate": 0.1, "max_depth": 6},
    "iforest": {"n_estimators": 200, "max_samples": "auto"},
    "mlp": {"batch_size": 512, "lr": 3e-3, "weight_decay": 1e-3, "max_epochs": 200, "patience": 10},
    "ae": {"batch_size": 512, "lr": 3e-3, "weight_decay": 0.0, "max_epochs": 200, "patience": 10},
    "lr": {"C": 1.0},
}
ARMS = ["rf", "xgb", "iforest", "mlp", "ae"]          # five mandatory families
OPTIONAL_ARMS = ["lr"]
SUPERVISED_ARMS = {"rf", "xgb", "mlp", "lr"}
UNSUPERVISED_ARMS = {"iforest", "ae"}                 # trained on benign rows only
ARM_DISPLAY = {
    "rf": "Random Forest", "xgb": "XGBoost", "iforest": "Isolation Forest",
    "mlp": "PyTorch MLP", "ae": "PyTorch autoencoder", "lr": "Logistic regression (sanity)",
}

# Search spaces (doc 04 section 5), used by Track A dev-fold random search only.
SEARCH_SPACES = {
    "rf": {"n_estimators": [200, 300, 400, 500], "max_depth": [None, 10, 15, 20, 25, 30],
           "min_samples_leaf": [1, 2, 3, 4, 5]},
    "xgb": {"n_estimators": [200, 300, 400, 500, 600], "learning_rate": [0.03, 0.05, 0.1, 0.15, 0.2],
            "max_depth": [3, 4, 5, 6, 7, 8]},
    "iforest": {"n_estimators": [100, 150, 200, 250, 300], "max_samples": ["auto", 256]},
    "mlp": {"batch_size": [256, 512, 1024], "lr": [1e-3, 2e-3, 3e-3, 5e-3, 1e-2],
            "weight_decay": [1e-4, 3e-4, 1e-3, 3e-3, 1e-2]},
    "ae": {"batch_size": [256, 512, 1024], "lr": [1e-3, 2e-3, 3e-3, 5e-3, 1e-2],
           "weight_decay": [0.0, 1e-5, 1e-4, 1e-3]},
    "lr": {"C": [0.01, 0.1, 1.0, 10.0, 100.0]},
}
MAX_SEARCH_TRIALS = 20
