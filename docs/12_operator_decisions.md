# 12. Operator decisions (kickoff Q&A, 2026-11-21)

Recorded verbatim in substance from the operator's answers. These extend docs 00–11.

| Q | Decision |
|---|---|
| 1 | Prompt E (libvirt) supplied: `docs/11_prompt_E_libvirt.md`. |
| 2 | Work lives in `docs_claude/dfir-triage-ml/` (own git repo); docs copied to `dfir-triage-ml/docs/`. |
| 3 | Assistant may install the Python version it needs; record it in `docs/PLAN.md`. |
| 4 | `findings.json` carries both `file_sha256` (`str or null`, SHA-256 of the on-disk file; null if none) and `record_sha256` (`str`, SHA-256 of the canonicalised JSON artifact row, matching `manifest.json`). |
| 5 | Only artifacts with at least one deterministic rule hit become `F-xxxx` findings (sorted by `ml_anomaly_score` desc). Top-K model-ranked artifacts with zero rule hits go to `leads` (`L-xxxx`, `technique_id: null`). `technique_id` in findings comes **only** from the triggered rule's ATT&CK mapping, never from ground-truth metadata. |
| 6 | No rule codebase exists. Write `src/rules/deterministic_rules.py` with 15 rules RULE-001..RULE-015 (list below). `rule_hit_count` stays in RULE_FEATURES (ablation + export only). |
| 7 | 16 techniques across 6 tactics; add T1548.002 (UAC bypass, fodhelper/ms-settings). Avoid ephemeral discovery one-liners unless they leave files/Prefetch/registry traces. 11 dev + 5 holdout (seeded stratified draw across tactics) x 3 variants = 48 attack runs + 3 control runs = 51 runs. Every variant leaves at least 2–3 observable artifacts. |
| 8 | No libguestfs. Collector (as Administrator) collects Prefetch and AppCompatCache (ShimCache). Amcache via VSS shadow copy or InventoryApplicationFile; fail-soft with `"amcache": {"status": "skipped", "reason": "locked_hive_no_vss"}` in manifest. |
| 9 | `techniques.yaml` is self-contained (parameterised commands, cleanup/verification metadata, 3 variants each); no atomic-red-team clone, no Invoke-AtomicRedTeam in the guest. Commands rendered on the host with randomised benign-looking names, sent over SSH via a neutral wrapper. |
| 10 | Drop sshd.exe, outer SSH launcher wrapper PIDs and the collector's own PID tree; keep technique and benign child processes. |
| 11 | Global SEED = 42 everywhere; separate draw seeds (holdout draw, bootstrap) logged in `src/config.py` and output metadata. CIC CSV: write Step 4 code now; tell the operator if the CSV is missing at inspection time. |
| 12 | Capacity: 1 operator + the assistant, 1 laptop. Scope: 1 VM profile, 16 techniques, 51 runs, all 5 families + SHAP on both tracks. |

## Rule list for `src/rules/deterministic_rules.py` (from proposal section 6.1, as given by the operator)

Run/RunOnce pointing to user-writable/temp paths or unsigned/script targets; scheduled task executing encoded PowerShell or LOLBins;
service binary in non-standard path; startup-folder script/.lnk calling a LOLBin; WMI event-subscription persistence;
rundll32/mshta/regsvr32/certutil proxy-execution patterns; unsigned EXE/DLL in Temp/AppData/Public/ProgramData;
hidden/system-attribute binary in a user-writable path; masqueraded system binary name outside System32;
UAC-bypass registry key under ms-settings/mscfile; IFEO / file-association persistence key;
local account creation or suspicious group change; event-log clear / defence-impairment indicator.

## `findings.json` schema (verbatim example from the operator)

```json
{
  "case_id": "CASE-2026-0001",
  "run_id": "run_001",
  "generated_at_utc": "2026-11-21T12:00:00Z",
  "manifest_sha256": "<sha256_of_run_manifest_json>",
  "ml_model_name": "xgboost",
  "findings": [
    {
      "finding_id": "F-0001",
      "category": "persistence | execution | defense_evasion | privilege_escalation | credential_access | discovery",
      "severity": "high | medium | low",
      "confidence": 0.90,
      "technique_id": "T1547.001",
      "rule_ids_triggered": ["RULE-001"],
      "ml_anomaly_score": 0.9412,
      "ml_rank": 1,
      "shap_top_features": [
        {"feature": "has_encoded_flag", "shap_value": 1.42, "feature_value": 1}
      ],
      "artifact_refs": [
        {
          "artifact_key": "run_key::hku\\s-1-5-21...\\software\\microsoft\\windows\\currentversion\\run::updater",
          "artifact_type": "run_key",
          "timestamp_utc": "2026-11-21T11:58:10Z",
          "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "record_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          "excluded_or_invalid": false
        }
      ],
      "extracted_iocs": {
        "file_paths": ["C:\\Users\\Public\\updater.ps1"],
        "sha256_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "urls_or_ips": []
      }
    }
  ],
  "leads": [
    {
      "lead_id": "L-0001",
      "ml_anomaly_score": 0.8831,
      "ml_rank": 2,
      "rule_ids_triggered": [],
      "technique_id": null,
      "shap_top_features": [
        {"feature": "name_entropy", "shap_value": 1.15, "feature_value": 4.82}
      ],
      "artifact_ref": {
        "artifact_key": "file::c:\\programdata\\sync\\hlp.dll",
        "artifact_type": "file",
        "timestamp_utc": "2026-11-21T11:58:22Z",
        "file_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "record_sha256": "7b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
        "excluded_or_invalid": false
      }
    }
  ]
}
```

Note: the values in this example are schema illustrations supplied by the operator, not results.

## Follow-up decisions (2026-11-21 — Steps 4–6 kickoff)

| Item | Decision |
|---|---|
| `Q-S1-1` (`artifact_key` separator) | Keep `\|` (`ARTIFACT_KEY_SEP = "\|"`) everywhere, including `manifest.json`, feature tables, and `findings.json` / `export_findings.py`. |
| `Q-S1-2` (Extra `artifact_type` levels) | Approved: keep `file`, `shimcache`, `wmi_subscription`, `registry`, `other`, `na` alongside the original 8 `ARTIFACT_TYPE_LEVELS` in `src/config.py`. |
| Win11 Libvirt Overlay Design | Persistent domain `win11` on `qemu:///system`, UEFI NVRAM (`win11_VARS.fd.base` -> `win11_VARS.fd`), TPM 2.0 (`tpm-crb`), MAC `52:54:00:ba:30:f3`. Each run destroys `win11` if running, replaces `win11_overlay.qcow2` backed by read-only `win11_base.qcow2`, restores `win11_VARS.fd` from `.base`, calls `virsh start win11`, waits for SSH + `post_ssh_settle_seconds: 20`, runs launchers/control + collector, shuts down `win11`, and deletes `win11_overlay.qcow2`. Never use `virsh create` transient domains. |

