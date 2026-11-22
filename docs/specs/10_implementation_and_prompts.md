# 10. Implementation Spec and AI Coding Prompts

For developers and AI coding assistants (Cursor, Claude, Copilot). Read `00_README.md` first. Everything here implements decisions D2 and D8 to D13.

## 1. Repository layout

```
dfir-triage-ml/
├── README.md                      # how to reproduce every table
├── requirements.txt               # pinned versions
├── collector/
│   ├── Collect-Artifacts.ps1      # read-only guest-side collector (Prompt A)
│   ├── manifest_schema.json
│   └── README.md
├── lab_automation/
│   ├── techniques.yaml            # id, tactic, split (dev|holdout), parameterised commands, variants
│   ├── benign_noise.ps1           # randomised, seeded benign activity
│   ├── run_one.py                 # one run: revert, interleave, collect, shutdown
│   ├── run_all.py                 # batch, resume, disk guard
│   └── provenance/                # host-side logs, one JSONL per run (never copied into the guest)
├── data/
│   ├── raw/runs/<run_id>/         # collector output + manifest
│   ├── interim/                   # per-run labelled artifacts
│   ├── processed/                 # dataset_v1.parquet (frozen), data_dictionary.md
│   ├── external/cic_malmem_2022/  # Obfuscated-MalMem2022.csv (not committed)
│   └── splits/                    # split manifests and hashes
├── src/
│   ├── config.py                  # FEATURES, ORACLE_FEATURES, seeds, paths
│   ├── data/
│   │   ├── sanitize.py            # forbidden-token assertion
│   │   ├── features.py            # the 20 features, entropy
│   │   ├── labeler.py             # diff + provenance labeling, baseline dedupe
│   │   ├── splits.py              # technique groups, hash buckets, Track B splits
│   │   └── cic_malmem.py          # loader, Category parser, assertions
│   ├── models/
│   │   ├── preprocess.py          # shared pipeline (all arms)
│   │   ├── sklearn_models.py      # RF, XGBoost, Isolation Forest, (LR)
│   │   ├── mlp.py                 # PyTorch tabular MLP
│   │   └── autoencoder.py         # PyTorch deep autoencoder
│   └── eval/
│       ├── metrics.py             # PR-AUC, P@k, R@k, FPR at recall, unseen recall at FPR
│       ├── run_track_a.py         # dev CV, tuning, one-time final evaluation
│       ├── run_track_b.py         # split 1 (leaky) and split 2 (family-grouped, rotation)
│       ├── ablations.py
│       ├── shap_explain.py
│       └── figures.py
├── tests/                         # sanitize, entropy, labeler, split-leakage tests
└── results/
    ├── tables/  figures/  models/  logs/
```

## 2. Locked 20-feature schema

All features are computed by `src/data/features.py`. Every arm uses the same shared preprocessing.

```python
# src/config.py
CATEGORICAL_FEATURES = [            # one-hot; every one has an "na" level
    "artifact_type",                # task, service, run_key, startup, prefetch, amcache, process, account
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
    "autostart_flag",               # configured to run at boot or logon (Run key, startup, auto service, logon/boot task)
]
FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES + BINARY_FEATURES
assert len(FEATURES) == 20

# Never in the main model:
ORACLE_FEATURES = ["file_age_minutes", "created_in_window"]   # oracle ablation only
RULE_FEATURES   = ["rule_hit_count"]                          # rule-hit ablation only
META_COLUMNS    = ["run_id", "technique_id", "variant", "launcher", "artifact_key"]
LABEL_COL       = "label"   # attacker_induced | benign_drift | baseline  -> binary y = (label == "attacker_induced")
assert not set(FEATURES) & set(ORACLE_FEATURES + RULE_FEATURES + META_COLUMNS + [LABEL_COL])
```

### Calculation specs

**Shannon entropy** (strings, over Unicode code points with no case folding; bytes, over the 256 byte values):

```
H(x) = - sum over distinct symbols s of  p(s) * log2 p(s),   p(s) = count(s) / len(x)
H(empty) = 0.0     # return max(0.0, value) to avoid -0.0
```
- `name_entropy`: H of the artifact's base name (no directory).
- `cmdline_entropy`: H of the full command-line string.
- `file_entropy`: H of the **first 1 MiB** of the file's bytes. Not defined for non-file artifacts (na).
- `cmdline_nonalnum_ratio`: (characters that are not alphanumeric) / length; 0 if empty.

**Missing values (shared pipeline):** categorical `na` is its own level. Numeric missing values are imputed with 0 and a missing-indicator column is added (`SimpleImputer(strategy="constant", fill_value=0, add_indicator=True)`). Scalers and encoders are fitted on training data only.

**LOLBIN_LIST** (fixed in `config.py`; extend only before the test set is frozen): certutil, mshta, regsvr32, rundll32, wmic, bitsadmin, cscript, wscript, msbuild, installutil, forfiles, schtasks, sc, reg (as a command-line token).

**Forbidden-token patterns (FE-08):**

```python
import re
FORBIDDEN_PATTERNS = [
    re.compile(r"(?<![A-Za-z])atomic(?:redteam|test|runner)?(?![A-Za-z])", re.I),
    re.compile(r"(?<![A-Za-z])invoke-atomic[A-Za-z-]*", re.I),
    re.compile(r"(?<![A-Za-z0-9])T1\d{3}(?:[._]\d{3})?(?![0-9])", re.I),   # T1053.005 and T1053_005
    re.compile(r"(?<![A-Za-z])ART(?![A-Za-z])"),                           # case-sensitive
]
# Unit tests must match: "AtomicRedTeam", "Atomic_Test_1", "Atomic Red Team", "T1053.005", "T1053_005", "ART", "ART_1"
# Unit tests must NOT match: "Start Menu", "smart.exe", "Party", "atomicwallet", "SMART"
```

## 3. Guardrail block (paste into the assistant's system prompt or rules file)

```
You are helping build research code for DFIR-Triage, a read-only forensic triage project.
Non-negotiable rules:
1. A model only RANKS artifacts. Never write code, text, or comments that present a model score as a verdict,
   proof, or evidence of compromise. Use "rank", "prioritise", "lead".
2. Collection is read-only. The collector must not modify the host (writes only to its own output directory).
3. Track A (generated data) is never split by random row. Group by technique_id; assign benign artifact_keys
   to train/test by hash of artifact_key. A key must never appear on both sides.
4. ORACLE_FEATURES (file_age_minutes, created_in_window), RULE_FEATURES (rule_hit_count), META_COLUMNS and the label
   are never inputs to a main model. They appear only in clearly named ablations.
5. Before computing any string feature, assert zero matches of FORBIDDEN_PATTERNS on every input string.
   Fail the build; do not silently scrub.
6. CIC-MalMem-2022: drop 'Category' from X before binary classification and assert that neither 'Class' nor
   'Category' is in X. The stratified 80/20 split is leaky by construction and must be labelled so in every output.
7. The test set is frozen: evaluation code refuses to run the final evaluation twice without --force, and logs every run.
8. Headline metric is PR-AUC (plus precision@k, recall@k, FPR at fixed recall). Never accuracy alone.
9. No live malware, no cloud LLM calls, no network calls at runtime, no autonomous remediation.
10. Fixed seeds, pinned versions, deterministic outputs. Every result file records the commit hash, seed and config.
11. Do not invent numbers. Do not write result values into text or comments.
When requirements conflict with these rules, stop and ask.
```

## 4. Prompt A: Read-only PowerShell collector and SHA-256 manifest

```
Context: use the guardrail block. Implement collector/Collect-Artifacts.ps1 (Windows PowerShell 5.1 compatible).

Goal: collect host artifacts read-only inside a lab Windows 10/11 VM and write them to an output directory given by
-OutDir (default C:\collector_out, outside system directories), one JSONL file per artifact type plus manifest.json.

Artifact types and fields (every record has: artifact_type, artifact_key, name, path, timestamps in UTC ISO-8601, raw fields):
- scheduled tasks: Get-ScheduledTask with actions (execute, arguments), triggers, principal, state
- services: Win32_Service via Get-CimInstance (name, display name, path name, start mode, account)
- Run/RunOnce: HKLM and HKCU Software\Microsoft\Windows\CurrentVersion\Run and RunOnce (name, value)
- startup folders: all-users and per-user (file metadata)
- prefetch: C:\Windows\Prefetch\*.pf file name, size, created, modified (name gives executable and path hash; full parsing is out of scope)
- amcache: the live hive is locked. Read it from a VSS shadow copy or from the powered-off VM disk mounted read-only.
  If neither works in the time available, skip Amcache and write a manifest entry stating it was skipped and why.
- processes: Get-CimInstance Win32_Process (pid, ppid, name, path, command line, creation time) plus parent name
- local accounts: Get-LocalUser (name, enabled, last logon, creation if available)
- for every collected file path that exists: size, attributes (hidden/system), signature (Get-AuthenticodeSignature
  status and subject), SHA-256 (Get-FileHash), first 1 MiB entropy inputs are computed later in Python, not here.

artifact_key = "<artifact_type>|<normalised lower-case path or key>|<name>".

Read-only constraints:
- Use only Get-* cmdlets, registry reads, and file reads opened with FileShare.ReadWrite and read access.
- No Set-*, New-*, Remove-*, Start-*, Stop-* except creating files inside -OutDir.
- Record any unavoidable system change in manifest.json under "host_changes".

manifest.json: collector version, SHA-256 of the script itself, hostname, operator (env), start/end UTC, PowerShell
version, per-output-file SHA-256 and row counts, list of skipped items with reasons, and a log of every command class used.

Deliverables: the script; manifest_schema.json; a Pester or plain-PowerShell smoke test that runs the collector and
verifies the manifest hashes match the files; collector/README.md with usage and the read-only statement.
Do not add network calls. Keep runtime under about 2 minutes on a typical lab VM and report the measured time.
```

## 5. Prompt B: Diff labeler, baseline hash-deduplication, and feature extractor

```
Context: use the guardrail block. Implement src/data/sanitize.py, src/data/features.py, src/data/labeler.py,
src/data/splits.py (benign hash buckets only in this prompt) and tests.

Inputs:
- data/raw/runs/<run_id>/ collector output (JSONL + manifest) for every run
- the baseline artifact set B for the VM (collector output taken at the baseline snapshot)
- lab_automation/provenance/<run_id>.jsonl (host-side: launcher=benign|attack, timestamp, action, expected artifact keys)
- lab_automation/techniques.yaml (technique_id, tactic, split=dev|holdout, variants)

Steps:
1. sanitize.py: FORBIDDEN_PATTERNS from the spec. assert_clean(rows) checks every feature-input string
   (name, path, command line, registry value, task name, service name). On any match raise SanitizationError,
   write results/logs/sanitization_failures.csv with artifact_key, field, matched text. Runner footprint paths
   listed in config.RUNNER_EXCLUDE_PATHS are removed first and counted in a log.
2. labeler.py: candidates = rows in P whose artifact_key is not in B or whose content hash differs.
   - attacker_induced: the provenance log attributes it to launcher=attack, or it matches the technique's expected artifacts
   - benign_drift: attributed to launcher=benign or to the OS
   - baseline: everything else
   Do NOT use timestamps or detection rules to label. Emit label_reason for every row.
   Emit a review sample file: 10% of attacker_induced and 100 benign_drift rows for human review.
3. Baseline and benign_drift deduplication: keep one row per artifact_key across runs for baseline and benign_drift keys
   (retain the list of run_ids where seen). Bucket function:
       bucket(key) = int(sha256(key.encode()).hexdigest()[:8], 16) % 100
   bucket >= 75 -> test pool; bucket < 75 -> development, dev fold = bucket % 5.
   attacker_induced rows keep technique_id as their group; they are never bucketed by hash.
4. features.py: compute exactly the 20 features in config.FEATURES, plus ORACLE_FEATURES (file_age_minutes relative to the
   baseline snapshot time, created_in_window relative to the run window) and rule_hit_count if rule output is present.
   Store oracle and rule columns in the parquet but expose them only through config.ORACLE_FEATURES / RULE_FEATURES.
   Implement Shannon entropy exactly as specified, with edge cases: empty, single repeated symbol, uniform bytes.
5. Write data/processed/dataset_v1.parquet, data_dictionary.md, and dataset statistics (rows per label, per technique, per run).

Tests (pytest):
- sanitize: the positive and negative strings in the spec
- entropy: H("")=0, H("aaaa")=0, H of 256 distinct bytes = 8.0
- leakage: no baseline/benign artifact_key appears in both the development and test pools
- label: no label is derived from timestamps or rule columns
- feature list: len(FEATURES)==20 and no overlap with oracle/rule/meta/label columns
Report counts after running on the dry-run data; do not invent them.
```

## 6. Prompt C: Five-model training suite (Track A and Track B)

```
Context: use the guardrail block. Implement src/models/*.py and src/eval/run_track_a.py, run_track_b.py, metrics.py.

Shared preprocessing (src/models/preprocess.py): ColumnTransformer with one-hot for CATEGORICAL_FEATURES,
SimpleImputer(constant 0, add_indicator=True) + StandardScaler for numeric, binary passthrough. Fit on training data only.
The same pipeline feeds all arms.

Arms:
1. RandomForestClassifier(class_weight="balanced_subsample")
2. XGBClassifier(tree_method="hist", scale_pos_weight=num_benign/num_attack)
3. IsolationForest trained ONLY on benign rows; score = -decision_function (higher = more anomalous)
4. PyTorch tabular MLP:
   Input -> Linear(128) -> BatchNorm1d -> ReLU -> Dropout(0.3)
         -> Linear(64)  -> BatchNorm1d -> ReLU -> Dropout(0.2)
         -> Linear(32)  -> ReLU -> Linear(1)
   Loss BCEWithLogitsLoss(pos_weight=num_benign/num_attack computed on the training split), optimizer AdamW,
   early stopping on validation PR-AUC (patience about 10) using a validation split grouped like the outer split.
5. PyTorch deep autoencoder:
   Input -> Linear(64) -> ReLU -> Linear(32) -> ReLU -> Linear(16)
         -> Linear(32) -> ReLU -> Linear(64) -> ReLU -> Linear(Input)
   Train ONLY on benign rows with MSE; scaler fitted on benign training rows; early stopping on benign validation loss;
   anomaly score = per-row reconstruction MSE.
Optional 6: LogisticRegression as a sanity baseline, kept in a separate function.

Track A (run_track_a.py):
- Load dataset_v1.parquet. y = (label == "attacker_induced"). X = config.FEATURES only.
- Development techniques: StratifiedGroupKFold(n_splits=5) grouped by technique_id; benign dev rows use fold = bucket % 5.
- Random search, at most 20 trials per arm, dev folds only, seeds 0..2, store all trial scores.
- Training-fraction runs at 25/50/100% of dev data for the training-size curve.
- Final evaluation: refit on all development data and evaluate once on the frozen test set (5 holdout techniques + test-pool
  benign keys). Require --final. Refuse a second --final without --force; log every attempt with timestamp and commit hash.
  Verify the stored test-set hash before evaluating.
- Metrics per arm: PR-AUC, precision@k and recall@k for k in (10, 50, 100), FPR on benign rows at recall 0.9,
  training time, inference time per 1,000 rows. Bootstrap over run_id for intervals. Per-technique table.
- Ablations (separate flags): + RULE_FEATURES; + ORACLE_FEATURES (label output "ORACLE UPPER BOUND, NOT A RESULT");
  drop feature groups; unsupervised arms trained on baseline-only vs baseline + benign_drift.

Track B (run_track_b.py), CIC-MalMem-2022:
- Load Obfuscated-MalMem2022.csv; assert shape (58596, 57); print and inspect distinct Category strings; write the family parser
  from what you see; assert exactly 15 families plus Benign.
- y = (Class == "Malware"). X = the 55 numeric feature columns. Assert "Category" not in X and "Class" not in X.
- Split 1 (label "LEAKY: reproduction of published setup only"): stratified 80/20, fixed seed. Report accuracy and PR-AUC.
- Split 2: hold out 3 unseen families (1 ransomware, 1 spyware, 1 trojan) chosen by a seeded draw, seed logged. Benign rows grouped by
  k-means clusters (about 50) assigned to train or test. Report PR-AUC and unseen-family recall at 1% and 5% benign FPR
  (threshold from a benign validation portion). Print the caveat that benign FPR is optimistic (SMOTE twins).
- Optional rotation: 5 rotations so every family is held out once; report mean and range.
- The same five arms and the same architectures.

Outputs: results/tables/*.csv, results/models/ (state dicts, sklearn pickles), results/logs/ with seed, config, commit hash.
Include unit tests for metrics (precision@k on a tiny known example) and a smoke test that all arms run on a 1,000-row sample.
Do not print or commit any result values into source files.
```

## 7. Prompt D: SHAP explanations and 300-DPI publication figures

```
Context: use the guardrail block. Implement src/eval/shap_explain.py and src/eval/figures.py.

SHAP (mandatory):
- XGBoost and RandomForest: shap.TreeExplainer on up to 2,000 test rows (stratified so attacker_induced rows are included).
- PyTorch MLP: shap.GradientExplainer with a background sample of 100 training rows; explain up to 500 test rows.
  If GradientExplainer fails on the model, fall back to KernelExplainer with the same background and report the fallback.
- Map one-hot and missing-indicator columns back to the original 20 features by summing absolute SHAP values.
- Save per-feature mean(|SHAP|) tables for each model, and compute Spearman rank correlation of the top-10 features across RF, XGBoost, MLP.
- Autoencoder: per-feature mean reconstruction error contribution on test attacker_induced vs benign rows.
  Isolation Forest: permutation importance on PR-AUC. (SHAP is not used for these two.)
- Run explanations on dev-fold models during development; produce final explanations from the final models only after the final evaluation.

Figures (save PNG and PDF, dpi=300, column widths 3.5 in single and 7.0 in double, serif or sans font consistent across all figures,
colour-blind-safe palette, with markers or line styles in addition to colour):
1. PR curves for the five arms (Track A, frozen test set)
2. Precision@k bars with run-level bootstrap intervals
3. FPR at recall 0.9 per arm
4. Training-size curve (PR-AUC vs training fraction) per arm
5. SHAP summary (beeswarm) for XGBoost
6. Bar chart comparing top-10 mean(|SHAP|) across RF, XGBoost, MLP
7. Track B: split 1 vs split 2 side by side per arm (split 1 labelled "leaky")
8. Ablation bars (rule features, oracle upper bound, feature groups)
9. Autoencoder reconstruction-error contribution per feature

Rules: read values only from results/tables/*.csv (no hard-coded numbers); axis labels with units; no titles inside the figure
(captions go in the paper); every figure has a function that regenerates it from the CSVs; write a figures manifest listing
file, source CSV, and commit hash. Do not interpret the results in comments or captions.
```

## 8. Order of work

1. Collector (Prompt A) and lab automation (see `05`).
2. Feature extractor, sanitization, labeler (Prompt B) on dry-run data.
3. Track B pipeline and all five arms (Prompt C) on Track B first, so PyTorch debugging happens while the lab runs.
4. Track A training after the dataset is frozen.
5. SHAP and figures (Prompt D) after the final evaluation.
6. Lab automation has no dedicated prompt here. Add one if the team wants an AI to write `run_one.py` and `run_all.py`.
