# Step C.6 — Varied Benign Workload Generator Design & Realism Gate (`IMP-06`, `OD-V2-12`)

**Status:** `Phase 1 Design Only (Zero Live VM Collection Code Written Here)`  
**Audit Script:** [`scripts/verify_stratified_shortcuts.py`](../../scripts/verify_stratified_shortcuts.py)

---

## 1. Root Cause Fixed from v1 (`IMP-06`)

In v1, `lab_automation/benign_noise.ps1` drew from 6 fixed string bodies, collapsing `221` benign dev scripts onto `18` unique `file_size_log` values and `30` `(file_size_log, file_entropy)` pairs, while producing **`0` benign `service` drift**, **`0` benign `registry` drift**, and **concentrating `unsigned` benign rows inside synthetic scripts**. Worse, the pre-launch shortcut audit used hard-coded `file_size=2048` and `file_head_histogram=[1]*256`, masking the quantization before collection.

---

## 2. Varied Benign Workload Design (v2 Stage A Pilot & Stage B)

1. **Software Roster & Procedural Admin Activity (`OD-V2-12`):**
   - Exercise genuinely installed tools already baked into the Win11 base image and disjoint test software packs: **Git**, **Python 3.12**, **7-Zip**, **Notepad++**, **Sysinternals** (`sigcheck`, `procdump`, `autorunsc`), plus procedural non-template PowerShell / Python / Batch scripts generated with variable comment blocks, AST depth, and real data files.
2. **Expanded Artifact-Type Coverage Inside Clean Benign Windows:**
   - **Benign Windows Services:** Legitimate `svchost.exe -k <Group>` and standalone vendor services spanning both `Auto` and `Manual` `start_mode`.
   - **Varied-Trigger Scheduled Tasks:** Rotate across `MSFT_TaskLogonTrigger` (`ONLOGON`), `MSFT_TaskBootTrigger` (`ONSTART`), `MSFT_TaskDailyTrigger` (`DAILY`), `MSFT_TaskRegistrationTrigger`, and `MSFT_TaskIdleTrigger` rather than one hard-coded `/SC ONCE /ST 23:55`.
   - **Benign Registry Edits:** Legitimate `HKCU\...\Run`, `HKLM\...\RunOnce`, and software configuration keys (`Vendor\App\Settings`).
   - **Legitimate Unsigned PE Binaries:** Include valid unsigned developer CLI utilities/tools (`ext_class == "exe"`, `signature_state == "unsigned"`) in user/tool paths so `signature_state == "unsigned"` is not a spurious near-deterministic malware proxy (`drop_signature` collapse).
3. **Disjoint `dev` vs. `blind_test` Host Profiles (`IMP-05`):**
   - Separate user names, root tool paths, service prefixes, task prefixes, run-key names, and RNG seed ranges across [`HOST_PROFILES`](../../scripts/verify_stratified_shortcuts.py) (`dev` vs `blind_test`) so **`0` benign `artifact_key`s** overlap between `dev` and `blind_test`.

---

## 3. Automated Pass/Fail Template-Quantization Gate

[`check_template_quantization`](../../scripts/verify_stratified_shortcuts.py) enforces ALL six criteria on generated/collected benign rows (`label == 0`) prior to unlocking large batches:

| Criterion | Threshold (PASS) | Purpose |
| :--- | :---: | :--- |
| **`unique_size_ratio`** (`nunique(file_size_log) / n_files`) | **`>= 0.60`** | Prevents few-template file size clustering (`v1 = 18/221 = 0.081` FAILS) |
| **`unique_size_entropy_pair_ratio`** (`nunique(size, entropy) / n_files`) | **`>= 0.75`** | Prevents body-template memorization in trees/MLP |
| **`max_single_size_share`** | **`<= 0.10`** | Ensures no single fixed file template exceeds `10%` of benign files |
| **`benign_services`** | **`> 0`** | Eliminates v1's `0`-service benign blind spot |
| **`benign_registry`** | **`> 0`** | Eliminates v1's `0`-registry benign blind spot |
| **`benign_unsigned_pes`** | **`> 0`** | Breaks the `unsigned == attack` signature shortcut |
