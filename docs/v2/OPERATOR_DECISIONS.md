# DFIR-Triage ML v2 — Operator Decisions & Onboarding Defaults

**Status:** `ALL ITEMS BELOW ARE PENDING MOKH'S CONFIRMATION`  
**Scope:** Phase 1 preparation defaults for v2. **Gate 0 is NOT signed off.** No malware may be acquired, downloaded, or executed, and no VM runs or host firewall/XML edits may be performed until Mokh confirms these decisions and completes Gate 0 verification.  
**Related Docs:** [`V2_PLAN.md`](V2_PLAN.md) | [`FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md) | [`v2/plan.md`](../../v2/plan.md) | [`IMPROVEMENT_ANALYSIS.md`](../IMPROVEMENT_ANALYSIS.md)

---

## Summary Table

| ID | Topic | Proposed v2 Default | Status |
| :--- | :--- | :--- | :--- |
| **`OD-V2-01`** | **Data targets (Families + Positives/Runs)** | `>= 25–30` total distinct malware families, `>= 10–15` distinct families in blind test (pilot decides feasibility); rough anchor `~300–500` positives across `100+` VM runs | **pending Mokh's confirmation** |
| **`OD-V2-02`** | **v1 data reuse (`emulated` stratum)** | Reuse frozen `dataset_v1.parquet` strictly as a 3rd `"emulated"` training-pool stratum (`dev` only); v2 blind test is **100% new**; reuse disclosed in all tables/reports | **pending Mokh's confirmation** |
| **`OD-V2-03`** | **Fake-internet responder** | `INetSim` on a **separate isolated Linux VM** (`inetsim-vm`) attached to `win11-isolated` (never on host OS, never in-guest FakeNet-NG) | **pending Mokh's confirmation** |
| **`OD-V2-04`** | **Offline artifact extraction** | **User-space offline parsing inside an unprivileged container** (`--network=none`, `--read-only`, `--cap-drop=ALL`, pure user-space QCOW2/NTFS/registry/EVTX/Amcache/Prefetch parsing); **never host-kernel mounts** of infected images | **pending Mokh's confirmation** |
| **`OD-V2-05`** | **Stage A pilot scope** | `~3` clean control boots + `6–8` non-test malware families × `1–2` runs (`executed` + `dormant`); pilot families stay strictly out of blind test | **pending Mokh's confirmation** |
| **`OD-V2-06`** | **Multi-seed & tuning budget** | `K = 5` seeds (`[42, 43, 44, 45, 46]`) for `--final` and learning curves; `30` equal trials per tuned model arm in nested dev CV | **pending Mokh's confirmation** |
| **`OD-V2-07`** | **Malware sample sourcing & quarantine vault** | Authorized research feed (e.g., MalwareBazaar / institutional repo), encrypted non-executable host vault (`chmod 0700` dir, `0400` AES-256 archive), SHA-256 manifest preflight; zero acquisition until Gate 0 sign-off | **pending Mokh's confirmation** |
| **`OD-V2-08`** | **Malware categories, family normalization & clustering** | Multi-category mix (Ransomware, InfoStealer, Loader/Dropper, RAT/Backdoor, Coinminer, Trojanized Installer); AVClass2/ClarAVy canonical family names + `ssdeep`/TLSH/imphash near-duplicate connected-component grouping | **pending Mokh's confirmation** |
| **`OD-V2-09`** | **Stratum mix (`executed` vs `dormant` vs `emulated`)** | Report `(a) executed` (~60–70% of real-malware runs), `(b) dormant` (~30–40% of real-malware runs), and `(c) emulated` (v1 `dev` only, 0% blind test) separately and pooled with weights disclosed | **pending Mokh's confirmation** |
| **`OD-V2-10`** | **Independent blinded human review** | Mokh + second independent reviewer on a stratified `20%` overlap slice for Cohen's $\kappa$; blinded exports hide `label`, `label_reason`, `launcher`, `technique_id`, `sample_family` and require `reviewer_id`, `reviewed_at_utc`, per-row notes | **pending Mokh's confirmation** |
| **`OD-V2-11`** | **Feature schema scope** | Keep locked v1 `full_20` (20) + `no_content` (18) as the primary dual-config benchmark; any new PE/Sysmon/Amcache features stay strictly in a separately reported `v2_extended` config | **pending Mokh's confirmation** |
| **`OD-V2-12`** | **Benign software roster & target test prevalence** | Varied real software (Git, Python, 7-Zip, Notepad++, Sysinternals, procedural scripts), benign services, varied-trigger tasks, benign registry edits, legitimate unsigned PEs; disjoint dev/test profiles; evaluate at full host-snapshot prevalence + hard-negative slices | **pending Mokh's confirmation** |

---

## Detailed Decision Records

### `OD-V2-01` — Data Targets Expressed in Families & Positives/Runs *(pending Mokh's confirmation)*
- **Decision:** Express primary scale targets in **distinct malware families** (`>= 25–30` total families, with `>= 10–15` distinct families held out in the blind test) in addition to row/run targets (`~300–500` total positives across `100+` VM runs).
- **Rationale:** v1 held out only `5` ATT&CK techniques (`33` test positives), limiting out-of-distribution generalization power. Because real malware variants of one family can exhibit multiple ATT&CK techniques, family-level sample size governs generalization variance (`IMP-05`). Stage A pilot yield measurements will determine final feasible counts before freezing Stage B targets.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-02` — v1 Data Reuse (`emulated` Training-Pool Stratum) *(pending Mokh's confirmation)*
- **Decision:** Reuse v1 (`data/processed/dataset_v1.parquet`: `1,549` rows, `103` `attacker_induced` across 16 simulated ATT&CK techniques) strictly as a third **`"emulated"` training-pool (`dev`) stratum only**. Zero v1 rows, benign `artifact_key`s, or v1 emulated techniques may enter the v2 blind test — the v2 blind test is **100% new**. Every v2 table and report must explicitly disclose the v1 `emulated` reuse.
- **Rationale:** Preserves v1 as a continuity/calibration anchor in training without contaminating the blind test with v1 template quantization or synthetic attack signatures.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-03` — Fake-Internet Responder Architecture *(pending Mokh's confirmation)*
- **Decision:** Deploy **INetSim** on a **separate isolated Linux VM** (`inetsim-vm`, `192.168.150.10`) attached solely to `win11-isolated` (`virbr1`), with zero host-facing services and zero WAN forwarding (`IMP-02`).
- **Rationale:** Avoids running network-facing fake services directly on the Linux host (eliminating host-exposed `INPUT` ports) and avoids in-guest FakeNet-NG interference/artifacts inside Windows 11 host telemetry.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-04` — Offline Overlay Extraction Toolchain *(pending Mokh's confirmation)*
- **Decision:** Extract artifacts after `virsh destroy` exclusively via **user-space offline parsing inside an unprivileged container** (`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`, using user-space QCOW2/NTFS/registry/EVTX/Amcache/Prefetch parsers such as `dissect`, `regipy`, `evtx`, `libscca`), and **NEVER mount infected disk images in the host kernel** (`mount`, `qemu-nbd` kernel block mount, or host NTFS3/FUSE kernel paths).
- **Rationale:** Prevents adversarial NTFS filesystem/image-parsing bugs or symlink attacks from affecting the host kernel while recovering `Amcache.hve` (`IMP-16`), `Sysmon` EVTX, registry hives, and `Prefetch` cleanly without VSS or live guest SSH (`IMP-02`).
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-05` — Stage A Pilot Scope *(pending Mokh's confirmation)*
- **Decision:** Run a dev-only calibration pilot of **`~3` clean control boots** + **`6–8` distinct non-test malware families × `1–2` runs** spanning both `executed` and `dormant` strata. Pilot families remain strictly outside the blind test pool.
- **Rationale:** Empirically measures clean detonation rate, verified `attacker_induced` yield per run, `ambiguous_unattributed` quarantine rate, benign diversity, and per-run disk/time cost before committing full Stage B run quotas.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-06` — Multi-Seed & Nested CV Compute Budget *(pending Mokh's confirmation)*
- **Decision:** Use **`K = 5` independent seeds** (`[42, 43, 44, 45, 46]`) for multi-seed `--final` evaluation (reporting per-seed mean ± std and the K-seed ensemble score) and learning curves, and **`30` equal trials per tuned model arm** (`rf`, `xgb`, `iforest`, `mlp`, `ae`, `lr`) in nested family-grouped dev CV (`IMP-08`, `IMP-09`).
- **Rationale:** Quantifies neural/stochastic seed variance that v1's 1-seed `--final` masked (`std = 0.0600` on v1 dev MLP) and eliminates unequal hyperparameter search budgets across arms within ASUS TUF A15 (24 GB RAM) runtime limits.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-07` — Malware Sample Sourcing & Quarantine Vault *(pending Mokh's confirmation)*
- **Decision:** Source samples exclusively from an authorized research/academic feed (e.g., MalwareBazaar or institutional malware collection) under recorded institutional/ethics approval; store outside the repository in an encrypted, non-executable quarantine vault (`chmod 0700` dir, `0400` AES-256 archive) with SHA-256 manifest preflight before injection. Zero acquisition prior to written Gate 0 sign-off.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-08` — Malware Categories, Family Normalization & Deduplication *(pending Mokh's confirmation)*
- **Decision:** Target balanced multi-category coverage across Ransomware, InfoStealer, Loader/Dropper, RAT/Backdoor, Coinminer, and Trojanized Installer; normalize canonical family labels via AVClass2/ClarAVy consensus and group near-duplicate binaries/packers via `ssdeep`/TLSH/imphash clustering before assigning `dev` vs `blind_test` (`IMP-05`).
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-09` — Evaluation Stratum Mix (`executed` / `dormant` / `emulated`) *(pending Mokh's confirmation)*
- **Decision:** Report every headline table separately for `(a) executed` (~60–70% of new real-malware runs), `(b) dormant` (~30–40% of new real-malware runs, static pre-execution binaries), and `(c) emulated` (v1 training-pool-only stratum, never in blind test), plus combined stratified summaries with exact weights disclosed.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-10` — Independent Blinded Human Review Ownership *(pending Mokh's confirmation)*
- **Decision:** Mokh acts as primary blinded reviewer alongside a second independent reviewer scoring a stratified `20%` overlap slice for inter-rater Cohen's $\kappa$ (`IMP-04`). Review packs strip `label`, `label_reason`, `launcher`, `technique_id`, and `sample_family`; validation requires `reviewer_id`, `reviewed_at_utc`, `human_label`, and non-empty per-row `human_notes`.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-11` — Feature Schema Scope (`full_20` / `no_content` vs `v2_extended`) *(pending Mokh's confirmation)*
- **Decision:** Retain v1's exact 20 features (`full_20`) and 18 features (`no_content`) as the primary dual-configuration benchmark (`IMP-07`). Any additive v2 features (PE headers/imports, richer Sysmon lineage, Amcache fields) live strictly in a separately reported `v2_extended` evaluation and never alter the primary `full_20`/`no_content` winner rule.
- **Status:** **`pending Mokh's confirmation`**

### `OD-V2-12` — Benign Software Roster & Target Test Prevalence *(pending Mokh's confirmation)*
- **Decision:** Replace v1's 6-template benign script generator with varied real software workloads (Git, Python, 7-Zip, Notepad++, Sysinternals, procedural admin scripts), benign Windows services, varied-trigger scheduled tasks (`ONLOGON`, `DAILY`, `ONCE`), benign registry edits, and legitimate unsigned PE binaries (`IMP-06`), using disjoint dev vs blind-test host profiles (`IMP-05`). Evaluate the blind test at full realistic host-snapshot prevalence alongside balanced/hard-negative diagnostic slices.
- **Status:** **`pending Mokh's confirmation`**

---

## Operator Sign-Off Checklist (Mokh)

- [ ] `OD-V2-01` — Family targets (`>= 25–30` total, `>= 10–15` blind test) & pilot-calibrated row targets *(pending Mokh's confirmation)*
- [ ] `OD-V2-02` — v1 reuse strictly as `dev`-only `"emulated"` stratum; 100% new blind test *(pending Mokh's confirmation)*
- [ ] `OD-V2-03` — INetSim on separate isolated Linux VM *(pending Mokh's confirmation)*
- [ ] `OD-V2-04` — User-space offline parsing in unprivileged container (zero host-kernel mounts) *(pending Mokh's confirmation)*
- [ ] `OD-V2-05` — Pilot scope (`~3` controls + `6–8` families × `1–2` runs) *(pending Mokh's confirmation)*
- [ ] `OD-V2-06` — `K = 5` seeds and `30` equal trials per tuned model *(pending Mokh's confirmation)*
- [ ] `OD-V2-07` — Authorized malware sourcing & Gate 0 quarantine vault rules *(pending Mokh's confirmation)*
- [ ] `OD-V2-08` — Categories, AVClass2/ClarAVy normalization & fuzzy-hash clustering *(pending Mokh's confirmation)*
- [ ] `OD-V2-09` — Stratum mix (`executed` / `dormant` / `emulated`) *(pending Mokh's confirmation)*
- [ ] `OD-V2-10` — Blinded human review ownership & 20% dual-review Cohen's $\kappa$ *(pending Mokh's confirmation)*
- [ ] `OD-V2-11` — Primary `full_20`/`no_content` continuity + isolated `v2_extended` *(pending Mokh's confirmation)*
- [ ] `OD-V2-12` — Benign software roster, unsigned PEs, services/registry drift & full-host test prevalence *(pending Mokh's confirmation)*
