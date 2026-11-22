# 05. Dataset Generation Playbook — Rev 2

## 1. Overview

```
Base VM -> install tools -> run benign script once -> baseline snapshot B
   |
   per run: revert to B -> boot -> [ benign noise (randomized)  ||  attack step ] interleaved in ONE window
            -> collect artifacts P -> shut down

Label = diff(P, B) + technique ground truth + host-side provenance log + human sample review
```

## 2. Lab setup (one profile, Day-1 target)

1. Hypervisor with a scriptable CLI (VMware `vmrun` or VirtualBox `VBoxManage`).
2. One Windows 10/11 VM: **6 to 8 GB RAM, 60 GB disk.** Install both office-style and developer tools in the same VM: Python, Git, VS Code, 7-Zip, Notepad++, Sysinternals, and a set of local HTML pages for offline browsing. This single VM replaces the two-profile plan.
3. Configure Defender with narrow exclusions only where a simulated technique needs it. Record the settings in run metadata. This is a limitation to state in the paper.
4. Stage Atomic Red Team prerequisites while online, then remove the network adapter or use a host-only network with no route out.
5. Take the baseline snapshot after the benign script has run once.
6. Second profile (Day-2 stretch, `Pri = S/C`): clone the VM and change installed software and user behaviour. Only start it if gate G1 passed.

## 3. Choosing techniques (15 to 18 curated, offline-safe)

- **10 to 12 development techniques** across 5 to 6 tactics.
- **5 frozen holdout techniques** from at least 4 tactics, chosen before looking at any data (seeded draw, seed recorded).
- Prefer techniques that need no tool download. Verify that each test exists and runs offline in the current Atomic Red Team repository.

| Tactic | Candidate technique IDs (verify) |
|---|---|
| Persistence | T1053.005 scheduled task, T1547.001 Run keys, T1543.003 new service, T1546.003 WMI subscription, T1136.001 local account |
| Execution | T1059.001 PowerShell, T1059.003 cmd |
| Defense evasion | T1036 masquerading, T1112 registry modification, T1070.001 clear logs, T1218 signed-binary proxy, T1562.001 impair defenses |
| Privilege escalation | T1574 DLL search order hijack |
| Discovery | T1082, T1083, T1087 (low footprint; hard cases) |

Variants: **3 to 4 per technique** (different file names, paths, arguments, parameter values). Total **45 to 65 runs.**

## 4. The benign-noise script (hard negatives inside the attack window)

Purpose: `benign_drift` artifacts must share the attacker's time window, so time alone cannot separate them.

- Randomized per run (seeded, seed logged): install and launch an app, open files, offline browsing, create a backup scheduled task, add a Run key for a normal app, run an admin PowerShell one-liner, use PsExec legitimately, software update.
- **Execution order:** the benign launcher and the attack launcher run as two separate launcher sessions on the guest, started from the host within the same short interval, with randomized interleaving of steps. The benign script does **not** run before `t_attack_start`.
- Both `t_start` and `t_end` bracket the entire interleaved window.

### Provenance log (ground truth for labels)

Kept **on the host**, outside the guest. Each action records: `run_id`, `launcher` (benign or attack), timestamp, action description, and the artifact keys it is expected to create. Labeling uses this log plus the baseline diff, not timestamps.

## 5. Run automation (per run)

1. Revert to snapshot B. Boot, wait for ready state.
2. Start the host-side provenance log.
3. Start the benign launcher and the attack launcher together (interleaved, randomized).
4. Wait for both with a timeout.
5. Run the collector. Copy output to the host.
6. Shut down. Log success or failure. Retry once on failure, log it.

`run_all.py` supports resume, continues after a failed run, and stops if free disk falls below a guard value (for example 30 GB).

## 6. Row schema and string sanitization

Columns are metadata, features, and labels. The **locked feature list is in `10_implementation_and_prompts.md`** (20 features, with `file_age_minutes` and `created_in_window` held in a separate `ORACLE_FEATURES` list).

| Group | Columns |
|---|---|
| Metadata (never features) | run_id, technique_id, variant, launcher, artifact_key |
| Features | the 20 locked features |
| Oracle (ablation only) | file_age_minutes, created_in_window |
| Rule features (ablation only) | rule_hit_count |
| Label (never a feature) | label |

### 6.1 String-sanitization rule (hard)

The model must not be able to learn "contains the simulation framework's name". Two layers:

**Generation side (DS-09).** Parameterize every payload so these never appear in artifact names or values:
- the literals `Atomic`, `AtomicRedTeam`, `ART` (and `Invoke-Atomic...` module or function names);
- technique IDs such as `T1053.005` or `T1053_005`;
- the runner's install directory and log paths.

Preferred approach: render the command from the atomic definition on the host and execute it through a neutral wrapper with neutral file names, rather than running the Atomic module inside the guest. If the module must run in the guest, keep its folder and logs out of the collector's scope (DS-10).

**Feature-extractor side (FE-08).** Before any string feature is computed, an automated check runs on every feature-input string (artifact name, path, command line, registry value, task name, service name) and **asserts zero matches** of the forbidden patterns defined in `10_implementation_and_prompts.md`. A match:
- fails the dataset build,
- writes the offending `artifact_key` list to `results/logs/sanitization_failures.csv`,
- is fixed at the source (payload or runner exclusion), not by silently deleting the token.

The check is an assertion, not a silent scrubber. A scrubber would hide the problem and alter `name_length` and `name_entropy`.

Required unit tests: positive cases (`AtomicRedTeam`, `Atomic_Test_1`, `T1053.005`, `T1053_005`, standalone `ART`), negative cases (`Start Menu`, `smart.exe`, `Party`, `atomicwallet`).

## 7. Labeling rules

1. Build the baseline artifact set B.
2. For each run, collect P. Rows in P with a key not in B, or changed versus B, are candidates.
3. `attacker_induced`: the provenance log shows the attack launcher produced it, or it matches the technique's known artifacts.
4. `benign_drift`: the benign launcher or the OS (updates, indexing, telemetry) produced it.
5. All other rows: `baseline`.
6. Runner footprint rows (DS-10) are dropped and logged.
7. Human review: at least 10% of `attacker_induced` and 100 `benign_drift` rows. Fix the rules where disagreements cluster, then re-run labeling.
8. Labels never come from the deterministic rules or from a model.

## 8. Leakage rules (do not weaken)

| Risk | Rule |
|---|---|
| Snapshot-clock oracles | `created_in_window` and `file_age_minutes` are **excluded from the main models** and reported only in the oracle ablation. |
| Benign activity outside the attack window | Benign noise runs inside the window (section 4), so time does not separate `benign_drift` from `attacker_induced`. |
| Repeated baseline rows | Deduplicate baseline rows across runs. Assign each baseline `artifact_key` to train or test by **hash of the key**, so one key is never in both. The same rule applies to `benign_drift` keys. |
| Simulation vocabulary | Section 6.1 assertion. |
| `rule_hit_count` | Not in the main model; ablation only. |
| Same technique in train and test | Split by technique (`07`). Variants of a technique stay together. |
| Tuning on the test set | Freeze and hash the test set before tuning. |
| Metadata columns | Never features. |
| Runner footprint | Excluded (DS-10). |

## 9. Expected data shape (estimate)

Thousands of rows per run, mostly baseline. After deduplication, expect tens of thousands to a few hundred thousand rows, with attacker-induced rows well under 5%. With 5 held-out techniques x 3 to 4 variants, the frozen test set may hold only on the order of a hundred positives or fewer. Measure on Day 1; if the count of positives in the 5 holdout techniques is below about 100, add variants for those techniques rather than adding techniques (the 100 is a planning threshold, not a statistical rule).

## 10. Optional memory add-on (stretch)

Hypervisor snapshot memory file, then Volatility 3 plugins (pslist, psxview, malfind, ldrmodules, dlllist, svcscan, netscan, handles, callbacks), extract features, delete the dump. Pre-cache symbol tables before disconnecting the network. Subset of runs only.
