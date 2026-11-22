# DFIR-Triage ML v2 — Operator Decisions & Onboarding Record

**Status:** `OD-V2-01..06, 08, 09, 11..19 CONFIRMED BY MOKH (2026-11-23); OD-V2-10 CHANGED & CONFIRMED (2026-11-23); OD-V2-07 DESIGN CONFIRMED — WRITTEN PROFESSOR/UNIVERSITY APPROVAL & GATE 0 SIGN-OFF REMAIN PENDING`  
**Single Source of Truth:** This document (decision records) together with [`docs/v2/V2_PLAN.md`](V2_PLAN.md) (v2 architecture, safety, methodology, and evaluation design) is the single source of truth for Phase v2.  
**Related Docs:** [`V2_PLAN.md`](V2_PLAN.md) | [`FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md) | [`v2/plan.md`](../../v2/plan.md) | [`IMPROVEMENT_ANALYSIS.md`](../IMPROVEMENT_ANALYSIS.md)

---

## Summary Table

| ID | Topic | Confirmed v2 Decision | Status |
| :--- | :--- | :--- | :--- |
| **`OD-V2-01`** | **Data targets (Families + Positives/Runs)** | `>= 25–30` total distinct malware families, `>= 10–15` distinct families in blind test (pilot decides what is feasible); rough anchor `~300–500` positives across `100+` VM runs | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-02`** | **v1 data reuse (`emulated` stratum)** | Reuse frozen `dataset_v1.parquet` strictly as a 3rd `"emulated"` training-pool stratum (`dev` only); v2 blind test is **100% new**; reuse disclosed in all tables/reports | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-03`** | **Fake-internet responder** | `INetSim` on a **separate isolated Linux VM** (`inetsim-vm`) attached to `win11-isolated` (never on host OS, never in-guest FakeNet-NG) | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-04`** | **Offline artifact extraction** | **User-space offline parsing inside an unprivileged container** (`--network=none`, `--read-only`, `--cap-drop=ALL`, pure user-space QCOW2/NTFS/registry/EVTX/Amcache/Prefetch parsing); **never host-kernel mounts** of infected images | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-05`** | **Stage A pilot scope** | `~3` clean control boots + `6–8` non-test malware families × paired `dormant` + `executed` runs per `sample_sha256` (`pair_group_id`, matching initial staging path); pilot families stay strictly out of blind test | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-06`** | **Multi-seed & tuning budget** | `K = 5` seeds (`[42, 43, 44, 45, 46]`) for `--final` and learning curves; `30` equal trials per tuned model arm in nested dev CV, **with a fallback to `20` trials if the pilot shows compute is too heavy** | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-07`** | **Malware sample sourcing & quarantine vault** | Authorized research feed (e.g., MalwareBazaar / institutional repo), encrypted non-executable host vault (`chmod 0700` dir, `0400` AES-256 archive), SHA-256 manifest preflight; zero acquisition until written professor/university approval & Gate 0 sign-off | **design confirmed by Mokh 2026-11-23; written professor/university approval & Gate 0 sign-off PENDING** |
| **`OD-V2-08`** | **Malware categories, family normalization & clustering** | Multi-category mix (Ransomware, InfoStealer, Loader/Dropper, RAT/Backdoor, Coinminer, Trojanized Installer), **preferring families that run without live C2 and leave persistence artifacts**; AVClass2/ClarAVy canonical family names + `ssdeep`/TLSH/imphash near-duplicate clustering | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-09`** | **Stratum mix (`executed` vs `dormant` vs `emulated`) & pairing** | Report `(a) executed` (~60–70% of real-malware runs), `(b) dormant` (~30–40% of real-malware runs), and `(c) emulated` (v1 `dev` only, 0% blind test) separately and pooled with weights disclosed; `dormant` and `executed` cross-stratum runs are **paired by `sample_sha256` (`pair_group_id`)** and never straddle `dev` and `blind_test` | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-10`** | **Independent blinded human review** | **CHANGED:** **Mokh's friend is the primary blinded reviewer; Mokh scores the 20% overlap slice for Cohen's $\kappa$** (because Mokh built the labeler and is not independent). Blinded exports hide `label`, `label_reason`, `launcher`, `technique_id`, `sample_family` and require `reviewer_id`, `reviewed_at_utc`, per-row notes | **CHANGED & confirmed by Mokh 2026-11-23** |
| **`OD-V2-11`** | **Feature schema scope** | Keep locked v1 `full_20` (20) + `no_content` (18) as the primary dual-config benchmark; add a separate secondary arm for the referential graph (`v2_refgraph`, see `OD-V2-13`), keeping any non-v1 features strictly outside `full_20`/`no_content` and the primary winner rule | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-12`** | **Benign software roster & target test prevalence** | Varied real software (Git, Python, 7-Zip, Notepad++, Sysinternals, procedural scripts), benign services, varied-trigger tasks, benign registry edits, legitimate unsigned PEs; disjoint dev/test profiles; **report natural (full-host snapshot) prevalence as the main view and a subsampled view as secondary, with weights disclosed** | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-13`** | **Referential-graph secondary arm (`v2_refgraph`)** | Secondary, pre-registered `"v2_refgraph"` config built ONLY from static cross-references inside the artifacts themselves (`ref_targets`, `ref_type`, `linked_artifact_keys`). Never uses labeling provenance, process trees, Sysmon, or timestamps. Never part of `full_20`/`no_content` or primary winner rule | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-14`** | **Tail-risk & analyst-effort metrics** | Secondary pre-registered metrics: worst-ranked positive rank, recall at review budgets (`k = 10/20/50/100`), positives in bottom 50%/90%, and `effort@recall` (50%/80%/90%); document random tail-audit sample-size upper bound $1 - 0.05^{1/n}$ ($n=5 \to 45\%$, $n=59 \to 5\%$, $n=300 \to 1\%$) as **future work only** | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-15`** | **Cross-Stratum Execution Delta (`executed` vs `dormant`)** | On paired `sample_sha256` binaries ($s \in \mathcal{S}_{\text{paired}}$ via `pair_group_id`), pre-register secondary comparison of $\Delta_{\text{exec}}(M, C)$ across `full_20`, `no_content`, `drop_signature`, `no_content_no_sig`, plus `Rank_min` ($\Delta_{\text{first\_hit}}$), Intrusion-Detection Recall@k, and the Byte/Signature Evasion Resilience Hypothesis ($|\Delta_{\text{ablation, executed}}| < |\Delta_{\text{ablation, dormant}}|$) *(and secondary `v2_refgraph`)* | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-16`** | **Offline pointer capture (`v2_refgraph`)** | Offline unprivileged-container extractor MUST store raw static pointer fields as schema-validated structured records (Prefetch file metrics, MFT records/seq, Tasks XML/TaskCache, Registry Run/Winlogon/IFEO/CLSID/Services, WMI, LNK, Amcache), extracting **zero executable payloads** and barred strictly from `full_20`/`no_content` via `FORBIDDEN_MODEL_INPUTS` | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-17`** | **Propagation baselines for `v2_refgraph`** | Pre-register 3 interpretable propagation baselines for secondary `v2_refgraph`: `(a)` base ranker alone, `(b)` naive undirected propagation, and `(c)` hub-attenuated typed propagation (context-split + training-pool IHF weights) — all transparent & traceable | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-18`** | **Heterogeneous GNNs deferred** | Heterogeneous Graph Neural Networks (`R-GCN`, `GAT`) are **deferred** and explicitly excluded from v2 core | **confirmed by Mokh 2026-11-23** |
| **`OD-V2-19`** | **Deferred post-v2-final stretch items** | Strictly post-`--final` stretch experiments (never delaying or gating v2 core): timestomp / temporal-baseline comparison, Prefetch-disabled server ablation, and external corpora (`ADFIR`, `NIST CFReDS`, `Magnet CTF`) as qualitative case studies with **zero tuning** | **confirmed by Mokh 2026-11-23** |

---

## Detailed Decision Records

### `OD-V2-01` — Data Targets Expressed in Families & Positives/Runs
- **Decision:** Express primary scale targets in **distinct malware families** (`>= 25–30` total families, with `>= 10–15` distinct families held out in the blind test) alongside rough run/positive anchors (`~300–500` total positives across `100+` VM runs). **The Stage A pilot decides what is feasible** before freezing Stage B targets.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-02` — v1 Data Reuse (`emulated` Training-Pool Stratum)
- **Decision:** Reuse frozen v1 (`data/processed/dataset_v1.parquet`: `1,549` rows, `103` `attacker_induced` across 16 simulated ATT&CK techniques) strictly as a third **`"emulated"` training-pool (`dev`) stratum only**. Zero v1 rows, benign `artifact_key`s, or v1 emulated techniques enter the v2 blind test — the v2 blind test is **100% new**, and v1 reuse is explicitly disclosed in every v2 manifest, table, and report.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-03` — Fake-Internet Responder Architecture
- **Decision:** Deploy **INetSim** on a **separate isolated Linux VM** (`inetsim-vm`, `192.168.150.10`) attached solely to `win11-isolated` (`virbr1`), with zero host-facing services and zero WAN forwarding (`IMP-02`).
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-04` — Offline Overlay Extraction Toolchain
- **Decision:** Extract artifacts after `virsh destroy` exclusively via **user-space offline parsing inside an unprivileged container** (`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`, pure user-space QCOW2/NTFS/registry/EVTX/Amcache/Prefetch parsers such as `dissect`, `regipy`, `evtx`, `libscca`), and **NEVER mount infected disk images in the host kernel**.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-05` — Stage A Pilot Scope
- **Decision:** Run a dev-only calibration pilot of **`~3` clean control boots** + **`6–8` distinct non-test malware families × paired `dormant` and `executed` runs per `sample_sha256` (`pair_group_id`)**, staging each binary at the identical initial path before detonation so cross-stratum execution shifts are measured on matched binaries. Pilot families and `sample_sha256` pairs remain strictly outside the blind test pool.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-06` — Multi-Seed & Nested CV Compute Budget
- **Decision:** Use **`K = 5` independent seeds** (`[42, 43, 44, 45, 46]`) for multi-seed `--final` evaluation (reporting per-seed mean ± std and the K-seed ensemble score) and learning curves, and **`30` equal trials per tuned model arm** (`rf`, `xgb`, `iforest`, `mlp`, `ae`, `lr`) in nested family-grouped dev CV, **with a pre-authorized fallback to `20` equal trials if the Stage A pilot shows compute is too heavy**.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-07` — Malware Sample Sourcing & Quarantine Vault
- **Decision:** Source samples exclusively from an authorized research/academic feed under recorded institutional approvals; store outside the repository in an encrypted, non-executable quarantine vault (`chmod 0700` dir, `0400` AES-256 archive) with SHA-256 manifest preflight before injection. **Written professor/university approval is still required, and Gate 0 remains unsigned.** Zero malware acquisition or execution may occur until both are completed.
- **Status:** **`design confirmed by Mokh 2026-11-23; written professor/university approval & Gate 0 sign-off PENDING`**

### `OD-V2-08` — Malware Categories, Family Normalization & Deduplication
- **Decision:** Target balanced multi-category coverage across Ransomware, InfoStealer, Loader/Dropper, RAT/Backdoor, Coinminer, and Trojanized Installer, **preferring families that execute meaningfully without live C2 infrastructure and leave host persistence artifacts**; normalize canonical family labels via AVClass2/ClarAVy consensus and group near-duplicate binaries/packers via `ssdeep`/TLSH/imphash clustering before assigning `dev` vs `blind_test` (`IMP-05`).
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-09` — Evaluation Stratum Mix (`executed` / `dormant` / `emulated`) & Paired Binary Design
- **Decision:** Report every headline table separately for `(a) executed` (~60–70% of new real-malware runs), `(b) dormant` (~30–40% of new real-malware runs, static pre-execution binaries), and `(c) emulated` (v1 `dev`-only continuity stratum, never in blind test), plus combined real-malware stratified summaries with exact weights disclosed.
  - **Paired `sample_sha256` Design (Stage A Pilot & Stage B Full Collection):** Cross-stratum `dormant` and `executed` evaluations MUST pair runs by exact `sample_sha256` (linked by forbidden provenance column `pair_group_id`, barred from `X` via `META_COLUMNS` / `FORBIDDEN_MODEL_INPUTS`), evaluating each binary both `dormant` (staged at a realistic path without execution) and `executed` (detonated from the matching initial staging path).
  - **Anti-Leakage Rule:** Both the `dormant` run and the `executed` run of any `sample_sha256` (along with its entire `sample_family` + `ssdeep`/TLSH cluster) MUST reside strictly in the same split pool (`dev` OR `blind_test` — never straddling `dev` and `blind_test`).
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-10` — Independent Blinded Human Review Ownership *(CHANGED)*
- **Decision:** **Mokh's friend acts as the primary blinded reviewer, and Mokh scores the stratified `20%` overlap slice for inter-rater Cohen's $\kappa$** (because Mokh built the v2 labeler and is therefore not an independent primary reviewer). Review packs strip `label`, `label_reason`, `launcher`, `technique_id`, and `sample_family`; validation requires `reviewer_id`, `reviewed_at_utc`, `human_label`, and non-empty per-row `human_notes`.
- **Status:** **`CHANGED & confirmed by Mokh 2026-11-23`**

### `OD-V2-11` — Feature Schema Scope (`full_20` / `no_content` + Secondary `v2_refgraph`)
- **Decision:** Retain v1's exact 20 features (`full_20`) and 18 features (`no_content`) as the primary dual-configuration benchmark (`IMP-07`). Add a separate secondary pre-registered arm for the static referential graph (`v2_refgraph`, `OD-V2-13`). Any additive features stay strictly outside `full_20`/`no_content` and never enter the primary dual-config winner rule.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-12` — Benign Software Roster & Target Test Prevalence
- **Decision:** Replace v1's 6-template benign script generator with varied real software workloads (Git, Python, 7-Zip, Notepad++, Sysinternals, procedural admin scripts), benign Windows services, varied-trigger scheduled tasks (`ONLOGON`, `DAILY`, `ONCE`), benign registry edits, and legitimate unsigned PE binaries (`IMP-06`), using disjoint dev vs blind-test host profiles (`IMP-05`). **Report natural (full-host snapshot) prevalence as the main blind-test evaluation view and a subsampled prevalence view as secondary, with stratum/sampling weights explicitly disclosed.**
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-13` — Referential-Graph Secondary Arm (`v2_refgraph`)
- **Decision:** Pre-register a secondary `"v2_refgraph"` configuration derived **strictly from static cross-references inside the artifacts themselves**:
  - Normalized extraction targets stored in `ref_targets`, edge relation types in `ref_type`, and offline-resolved keys in `linked_artifact_keys` (e.g., Run key value -> target image path, service `ImagePath` -> binary, scheduled task action -> script/binary, Prefetch referenced files).
  - **Strict anti-leakage constraint:** Links must **NEVER** inspect labeling provenance, Sysmon event logs, process trees, or timestamps (which would leak ground truth). Raw edge columns (`ref_targets`, `ref_type`, `linked_artifact_keys`) are barred from `full_20` and `no_content` via `FORBIDDEN_MODEL_INPUTS`; only the dedicated `v2_refgraph` feature builder may read them.
  - Strictly secondary and **never** part of `full_20`/`no_content` or the primary dual-config winner rule.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-14` — Tail-Risk & Analyst-Effort Metrics
- **Decision:** Add pre-registered secondary tail-risk and analyst-effort metrics to evaluation outputs:
  - Rank of the worst-ranked positive (`worst_positive_rank` and normalized rank percentile),
  - Recall at analyst review budgets (`k in {10, 20, 50, 100}`),
  - Positives falling in the bottom 50% and bottom 90% of model scores (`pos_in_bottom_50pct`, `pos_in_bottom_90pct`),
  - Artifacts reviewed to reach target recall (`effort@recall` at 50%, 80%, and 90% recall, both absolute count and fraction of artifacts).
  - Document the random tail-audit sample-size calculator: observing `0` missed positives in `n` uniform random draws from the tail gives a 95% Clopper-Pearson upper-bound miss rate of $p_{\text{upper}}(n) = 1 - 0.05^{1/n}$ (e.g., $n = 5 \to 45.1\%$, $n = 59 \to 5.0\%$, $n = 300 \to 1.0\%$). Any live/field tail audit is explicitly documented as **future work only**.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-15` — Cross-Stratum Execution Delta (`executed` vs `dormant` on Paired Binaries)
- **Decision:** On `sample_sha256`-paired binaries ($s \in \mathcal{S}_{\text{paired}}$, linked by forbidden provenance column `pair_group_id`), pre-register a secondary Cross-Stratum Execution Delta analysis measuring how detonation shifts triage detectability relative to pre-execution dormant staging:
  1. **Stratum-Conditional PR-AUC & Recall@k Delta ($\Delta_{\text{exec}}$):** $\Delta_{\text{exec}}(M, C) = \text{Metric}(M, C \mid \text{executed}) - \text{Metric}(M, C \mid \text{dormant})$ across $C \in \{\text{full\_20}, \text{no\_content}, \text{drop\_signature}, \text{no\_content\_no\_sig}\}$ (plus secondary `v2_refgraph`) with family-clustered paired bootstrap 95% CIs (resampling whole families/clusters so paired `executed` and `dormant` runs of family $f$ stay together).
  2. **Sample-Level First-Detection Rank / Effort Delta ($\Delta_{\text{first\_hit}}$):** Prevalence-invariant intrusion-level comparison using $\text{Rank}_{\min}(s, \text{stratum})$ (rank and normalized percentile effort of the highest-scored `attacker_induced` artifact produced by sample $s$ within its host run), reporting median and IQR of $\text{Rank}_{\min}(s, \text{dormant}) - \text{Rank}_{\min}(s, \text{executed})$ alongside **Intrusion-Detection Recall@k** ($k \in \{5, 10, 20, 50\}$).
  3. **Byte/Signature Evasion Resilience Hypothesis:** Pre-register the secondary test that removing byte/signature features causes severe degradation under `dormant` staging ($\Delta_{\text{ablation, dormant}}$) whereas post-detonation OS footprints preserve ranking performance ($|\Delta_{\text{ablation, executed}}| < |\Delta_{\text{ablation, dormant}}|$, tested via family-clustered paired bootstrap CI).
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-16` — Offline Pointer Capture Schema (`v2_refgraph`)
- **Decision:** Extend the offline user-space container extractor (`OD-V2-04`) to capture raw static pointer fields as **schema-validated structured records** (no executable payloads copied out of overlays) spanning Prefetch, `$MFT`, Scheduled Tasks (`XML` + `TaskCache`), Registry (`Run`/`RunOnce`/`Winlogon`/`IFEO`, `CLSID` `InprocServer32`/`LocalServer32`, `Services` + `ServiceDll`), WMI (`OBJECTS.DATA` filters/consumers/bindings), LNK (`BEEF0004` MFT ref / `ObjectId` / volume serial), and Amcache (`FileId`, `LowerCaseLongPath`). All extracted pointer columns and raw edge attributes remain strictly barred from `full_20` and `no_content` via `FORBIDDEN_MODEL_INPUTS`.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-17` — Interpretable Propagation Baselines for `v2_refgraph`
- **Decision:** Evaluate the secondary `v2_refgraph` arm using three interpretable, traceable propagation variants: `(a)` base ranker alone (out-of-fold local node scores, unpropagated), `(b)` naive undirected propagation over unsplit merged nodes, and `(c)` hub-attenuated typed propagation (context-scoped virtual node splitting + unidirectional `EXECUTES_IMAGE` + training-pool-only Inverse Host Frequency weighted directed edges).
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-18` — Deferment of Heterogeneous GNNs (`R-GCN`, `GAT`)
- **Decision:** Heterogeneous GNN architectures (`R-GCN`, `GAT`) are **deferred** and excluded from v2 core so that every `v2_refgraph` score remains forensically transparent and traceable to explicit static pointer paths.
- **Status:** **`confirmed by Mokh 2026-11-23`**

### `OD-V2-19` — Deferred Post-v2-Final Stretch Items
- **Decision:** Strictly **only after** the v2 `--final` evaluation completes, reserve the following as optional post-v2 stretch items (never gating v2 core):
  1. Timestomp / temporal-windowed baseline sensitivity experiment,
  2. Prefetch-disabled Windows Server ablation,
  3. Public external forensic corpora (`ADFIR`, `NIST CFReDS`, `Magnet CTF`) as **qualitative case studies with zero model tuning**.
- **Status:** **`confirmed by Mokh 2026-11-23`**

---

## Operator Sign-Off Checklist (Mokh)

- [x] `OD-V2-01` — Family targets (`>= 25–30` total, `>= 10–15` blind test; pilot decides feasibility) *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-02` — v1 reuse strictly as `dev`-only `"emulated"` stratum; 100% new blind test *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-03` — INetSim on separate isolated Linux VM *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-04` — User-space offline parsing in unprivileged container (zero host-kernel mounts) *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-05` — Pilot scope (`~3` controls + `6–8` families × paired `dormant` + `executed` runs per `sample_sha256` / `pair_group_id`) *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-06` — `K = 5` seeds and `30` equal trials per tuned model (`20`-trial fallback if pilot compute too heavy) *(confirmed by Mokh 2026-11-23)*
- [ ] `OD-V2-07` — Quarantine vault & SHA-256 manifest design confirmed (`2026-11-23`); **written professor/university approval & Gate 0 sign-off PENDING**
- [x] `OD-V2-08` — Categories, AVClass2/ClarAVy normalization, fuzzy-hash clustering, prefer no-live-C2 persistence families *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-09` — Stratum mix (`executed` ~60–70% / `dormant` ~30–40%, paired by `sample_sha256` / `pair_group_id` within same split / `emulated` `dev`-only) *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-10` — Friend primary blinded reviewer + Mokh scores 20% overlap for Cohen's $\kappa$ *(CHANGED & confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-11` — Primary `full_20`/`no_content` continuity + separate secondary `v2_refgraph` arm *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-12` — Varied benign roster; natural prevalence main view + subsampled secondary view (weights disclosed) *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-13` — Static-only referential-graph arm (`v2_refgraph`), barred from `full_20`/`no_content` & winner rule *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-14` — Tail-risk & effort metrics + $1 - 0.05^{1/n}$ tail-audit calculator (tail audit = future work only) *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-15` — Cross-Stratum Execution Delta (`Delta_exec`, `Rank_min` / `Delta_first_hit`, Intrusion-Detection Recall@k, Byte/Signature Evasion Resilience Hypothesis across `full_20`, `no_content`, `drop_signature`, `no_content_no_sig`, `v2_refgraph`) *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-16` — Offline pointer capture as schema-validated structured records (no payloads), barred from `full_20`/`no_content` *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-17` — Three interpretable propagation baselines for `v2_refgraph` (base alone, naive undirected, hub-attenuated typed) *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-18` — Heterogeneous GNNs (`R-GCN`, `GAT`) deferred, outside v2 core *(confirmed by Mokh 2026-11-23)*
- [x] `OD-V2-19` — Post-v2-final deferred stretch (timestomp experiment, Prefetch-disabled server ablation, `ADFIR`/`NIST CFReDS`/`Magnet CTF` qualitative case studies with zero tuning) *(confirmed by Mokh 2026-11-23)*
