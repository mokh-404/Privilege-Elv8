# DFIR-Triage Track A Dataset (`dataset_v1.parquet`) Data Dictionary

## Model Input Features (`config.FEATURES`, 20 columns)
| Column | Kind | Description |
|---|---|---|
| `artifact_type` | categorical | Levels: task, service, run_key, startup, prefetch, amcache, process, account, file, shimcache, wmi_subscription, registry, other, na |
| `path_class` | categorical | Levels: system, program_files, user_writable, temp, appdata, other, na |
| `ext_class` | categorical | Levels: exe, dll, script, shortcut, doc, other, na |
| `signature_state` | categorical | Levels: signed_trusted, signed_untrusted, unsigned, na |
| `parent_process_class` | categorical | Levels: explorer, services, svchost, cmd, powershell, office, browser, other, na |
| `registry_location_class` | categorical | Levels: run, runonce, services, winlogon, ifeo, other, na |
| `path_depth` | numeric | Computed by `src/data/features.py` |
| `name_length` | numeric | Computed by `src/data/features.py` |
| `name_entropy` | numeric | Computed by `src/data/features.py` |
| `file_size_log` | numeric | Computed by `src/data/features.py` |
| `file_entropy` | numeric | Computed by `src/data/features.py` |
| `cmdline_length` | numeric | Computed by `src/data/features.py` |
| `cmdline_entropy` | numeric | Computed by `src/data/features.py` |
| `cmdline_nonalnum_ratio` | numeric | Computed by `src/data/features.py` |
| `has_double_extension` | binary (0/1) | Computed by `src/data/features.py` |
| `has_encoded_flag` | binary (0/1) | Computed by `src/data/features.py` |
| `has_url_or_ip` | binary (0/1) | Computed by `src/data/features.py` |
| `has_lolbin` | binary (0/1) | Computed by `src/data/features.py` |
| `has_hidden_attr` | binary (0/1) | Computed by `src/data/features.py` |
| `autostart_flag` | binary (0/1) | Computed by `src/data/features.py` |

## Excluded From Primary Benchmark (Leakage / Metadata / Ablation Only)
| Column | Group | Purpose |
|---|---|---|
| `file_age_minutes`, `created_in_window` | `ORACLE_FEATURES` | Oracle upper-bound ablation only |
| `rule_hit_count` | `RULE_FEATURES` | Rule-hit ablation & `export_findings.py` only |
| `run_id`, `technique_id`, `variant`, `launcher`, `artifact_key` | `META_COLUMNS` | Grouping, provenance, deduplication |
| `label`, `label_reason`, `split_pool`, `dev_fold`, `seen_run_ids`, `seen_count` | Label / split | Supervision & leakage-proof split metadata |
