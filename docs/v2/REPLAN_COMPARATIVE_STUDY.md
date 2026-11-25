# DFIR-Triage ML v2 — Comparative Study Re-Scope & Execution Plan

**Status:** `LOCKED & APPROVED (2026-11-25) — MOKH + SUPERVISOR MARAWAN APPROVAL; SPRINT 1 IMPLEMENTED`  
**Companion Audit:** [`PIVOT_CODEBASE_AUDIT.md`](PIVOT_CODEBASE_AUDIT.md) (`317 passed` baseline; Sprint 1 safety/curator/pilot/benign/docs upgrade)  
**Target Artifact Pool:** `1,000` usable real malware samples (`800` dev / `200` blind test) + `200` benign-only runs (`160` dev / `40` blind test)

### Executive Framing of the Strategic Pivot
1. **Paper Framing:** The final thesis/paper is a **decisive comparative study of ML, Learning-to-Rank (LTR), deep tabular, unsupervised, and deterministic-rule baselines** on realistic Windows 11 cold-disk host artifacts (`~4,414` artifacts/host), demonstrating empirically why a realistic provenance-labeled Windows 11 corpus outperforms static/emulated benchmarks. Phase v1 (`dataset_v1.parquet`, permanently frozen) is **not** a separate paper — it is cited solely as the initial baseline motivating v2's scale, offline user-space extractor, and hardened isolation.
2. **Descoped Items:** `v2_refgraph` (dead-disk referential graph) is **descoped** from v2 core (existing pointer capture in [`offline_extractor.py`](../../src/v2/offline_extractor.py) stays untouched so regression tests remain green, with zero further refgraph development). Red-vs-Blue agents are **excluded** from v2.
3. **Both Malware States Retained Without Novelty Claims:** Every usable sample is evaluated in **both** `executed` and `dormant` ("stale") states. Every headline table reports `executed`, `dormant`, and pooled real-malware metrics separately alongside v1 `emulated` (`dev`-only). The `executed` vs. `dormant` contrast is reported strictly as a **plain descriptive table with zero novelty claim**.
4. **Approved Safety & Governance Gate:** Supervisor Marawan (AASTMT) granted approval on `2026-11-25` to proceed with Tier 2 Target scaling (`1,000` usable / `~2,000+` attempts + `200` benign runs, Tier 1 `400` usable Checkpoint 1) under strict hard exclusion of **ransomware, wipers, and self-propagating worms**. All 6 audited safety gaps from [`PIVOT_CODEBASE_AUDIT.md` §2](PIVOT_CODEBASE_AUDIT.md#2-audit-of-the-6-pending-safety-items-done--partial--gap) are implemented in Sprint 1 prior to host vault sign-off (`0400` `GATE0_SIGNED_OFF`) and `--canary` smoke verification.

---

## 1. Data Unit, Prevalence Policy & Projected Dataset Dimensions

### 1.1 Exact Data Unit Hierarchy
| Unit | Definition | Key / Identifier | Measured Cardinality (Host Parity Runs) |
| :--- | :--- | :--- | :--- |
| **File (`sample_sha256`)** | One unique standalone runnable `.exe` PE binary (`pe.is_exe() and not pe.is_dll()`) retrieved from MalwareBazaar and verified in RAM. | `sample_sha256` | `1,000` usable real files (`~2,000` raw attempted) + `0` in benign runs |
| **Sample (`pair_group_id`)** | The analytical subject pairing **both execution states** (`executed` + `dormant`) of one usable `sample_sha256` staged at the identical initial `C:\` path. | `pair_group_id` | `1,000` paired samples (`800` dev, `200` blind test) |
| **Run (`run_id`)** | One clean overlay execution/collection snapshot of a Windows 11 host (1 executed sample, 1 blind-test dormant sample, batched dev dormant samples, or 1 benign-only workload). | `run_id` | **`1` host snapshot** yielding **`4,414` raw cold-disk rows** (`4,413` clean base; `8` harness rows dropped) |
| **Row (Artifact Record)** | One normalized forensic artifact row (`file`, `task`, `service`, `run_key`, `startup`, `prefetch`, `amcache`, `shimcache`, `wmi_subscription`, `registry`, `account`, `other`; `0` live `process` rows). | `(run_id, artifact_key)` | **Baseline OS:** `~4,364–4,413` / host<br>**`benign_drift`:** `~30–80` / run<br>**`attacker_induced`:** `1` (`dormant`) / `~4–10` (`executed`, anchor `6`)<br>**`ambiguous_unattributed`:** `~5–20` / run (quarantined before scoring) |

### 1.2 Explicit Separation: Train-Time OS-Baseline Deduplication vs. Blind-Test Natural Prevalence
Naively concatenating `800` executed dev runs, `800` dormant dev observations, and `160` benign-only dev runs produces **`~7.83M` raw dev rows**, of which **`98.9%` are byte-for-byte identical untouched Windows 11 OS files** already frozen inside `win11_base.qcow2` (`d2facced...`).

To prevent CPU/RAM exhaustion without distorting real-world deployment prevalence:
1. **Training / Dev Only — Cross-Run OS-Baseline Deduplication (Pointwise & Unsupervised Models):**
   - Inside `dev` training folds **only**, collapse identical untouched `baseline` rows matching `(artifact_key, stable_content_hash)` across dev runs to a **single canonical OS-baseline exemplar per `(artifact_key, stable_content_hash)`** (~`4,500–5,500` unique baseline rows).
   - Keep **100% of `benign_drift` rows** across every dev run (`~50k–80k` rows — capturing realistic software/script variability) and **100% of `attacker_induced` rows** (`~4,800` executed + `800` dormant = `~5,600` positives).
   - Result: compact, diverse **`dev_dedup` pool of `~61k–91k` rows** (`~6.1%–9.2%` positive prevalence) plus `1,104` cold-disk rows from frozen v1 `emulated` `dev` (used strictly in `H3` transfer/mixed-training arms).
   - *Invariant:* Cross-run deduplication runs strictly **inside each outer/inner training partition** so zero baseline signatures leak across fold/pool checks.
2. **Training / Dev Only — Per-Run Query Groups for Learning-to-Rank (`XGBRanker`, `LGBMRanker`):**
   - Pairwise/listwise rankers require per-host `qid = run_id` groups containing both positives and realistic OS negatives from the same host snapshot.
   - For each positive-bearing dev run (`800` executed + `800` dormant), retain **all** `attacker_induced` rows + **all** `benign_drift` rows of that run + a deterministic stratified `K_neg = 200` sample of that run's `baseline` rows (~`250–290` rows/run -> **`~400k` total dev LTR rows across `1,600` query groups**).
3. **Blind-Test Evaluation — NEVER Deduplicated Across Runs:**
   - **Main Blind-Test View (`Natural Prevalence`, `OD-V2-12`):** Every test host snapshot retains **100% of its `~4,414+` artifacts intact**. Zero cross-run baseline deduplication occurs on the blind test set. Models are evaluated both **pooled** (cluster-bootstrapped PR-AUC, tail-risk, calibration, clean-host FPR across the `40` benign-only hosts) and **per-host macro-averaged** (`AP@host`, `Recall@k`, `Rank_min`, `Effort@Recall`).
   - **Secondary Blind-Test View (`Benign-Subsampled`, `OD-V2-12`):** Retain 100% of test positives (`~1,400`) + deterministic stratified benign subsampling (`200` benign rows per test run -> `48,000` benign rows + `1,400` positives = `~49,400` rows, `~2.83%` prevalence), with exact inverse-probability sampling weights disclosed for comparison against `dev_dedup` / literature prevalence regimes.

### 1.3 Projected Row Counts & Ratios at Target Scale (`1,000` Samples + `200` Benign Runs)

| Dataset Partition / View | Runs / Snapshots | Total Rows | Positives (`attacker_induced`) | Benign (`baseline + drift`) | Positive Ratio | Notes |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| **Dev Raw Uncollapsed** *(storage/provenance only)* | `1,760` (`800` exec + `800` dorm equiv. + `160` ben) | `~7,830,000` | `~5,600` | `~7,824,400` | `0.0715%` | Archive shard JSONLs (`~1.2 GB` zstd/gz); never loaded whole into estimators |
| **Dev Train Pool (`dev_dedup`, Pointwise/Unsup)** | `1,760` source runs | `~61,000–91,000` | `~5,600` (`~4,800` exec + `800` dorm) | `~55,000–85,000` (`~5k` canonical OS + `~50k–80k` drift) | `6.1%–9.2%` | Fast CV across all 20 models; excludes `ambiguous_unattributed` |
| **Dev Train Pool (`dev_ltr`, Query-Grouped)** | `1,600` host queries (`qid=run_id`) | `~400,000` | `~5,600` | `~394,400` | `1.40%` | Stratifies OS baseline (`200`/host) + all drift inside each host query |
| **v1 `emulated` `dev` (Transfer Arms Only)** | `16` dev techniques | `1,104` | `~77` | `~1,027` | `~6.97%` | Excludes `75` live `process` rows (`OD-V2-02`); `0%` in blind test |
| **Blind Test — `executed` Only (`Natural`)** | `200` runs (`1` sample/boot) | `~894,000` | `~1,200` (`~6`/run) | `~892,800` | `0.134%` | Headline per-state executed view |
| **Blind Test — `dormant` Only (`Natural`)** | `200` runs (`1` sample/boot) | `~890,000` | `200` (`1`/run) | `~889,800` | `0.0225%` | Headline per-state dormant view (strictly 1/boot) |
| **Blind Test — `benign`-Only Clean Hosts (`Natural`)** | `40` runs | `~178,000` | `0` | `~178,000` | `0.00%` | Measures false-positive alerts per clean host at calibrated thresholds |
| **Blind Test — Pooled `MAIN VIEW` (`Natural`)** | **`440` independent hosts** | **`~1,962,000`** | **`~1,400`** | **`~1,960,600`** | **`0.0714%`** | **Primary paper evaluation; zero cross-run deduplication** |
| **Blind Test — `SECONDARY VIEW` (`Subsampled`)** | `440` hosts (`200` ben/run) | `~89,400` | `~1,400` | `~88,000` | `1.57%` | Reported alongside main view with explicit sampling weights |

---

## 2. Feasibility Analysis with MEASURED Host Numbers & 3 Scale Tiers

### 2.1 Measured Per-Run Wall-Clock Breakdown
From Mokh's `2026-11-23` live runs on `win11_base.qcow2` (`d2facced...`) and container logs:
- **Guest Boot + Poweroff Overhead:** `~70s` (measured `100s` total poweroff on a `30s`-dwell parity boot -> `70s` fixed Windows boot + `\DFIR-StageRunner` + flush/shutdown; `210s` on `120s` dwell).
- **`(a)` Container Extraction Speedup (`192.9s -> ~20–25s`):**
  - Currently `192.9s` **only** because `win11_base_cache.json.gz` predates `MAX_PE_SIGNIFY_BYTES = 128 MiB`, causing [`stale_large_pe_hit`](../../src/v2/offline_extractor.py#L1090-L1095) (`base_cache_misses: 7`, `160.45s` wasted on `OneDriveSetup.exe` `89.7 MiB`).
  - Rebuilding `win11_base_cache.json.gz` once (`~3 min`) restores **`~20.5–25s`** extraction (**saving `~104+ hours` across ~2,250–2,450 runs**).
- **Base-Hash Verification Amortization:** Running full `sha256sum` on `129 GiB` `win11_base.qcow2` takes `~50–90s` per check (`100–180s/run` if run both before & after). With `chattr +i` + `0444` + `stat` inode/size/blocks + full `528 KiB` NVRAM SHA-256 every run + full `win11_base.qcow2` `sha256sum -c` every `25` runs, per-run verification drops from `~120s` to **`< 2s`**, saving an additional **`~70–80 hours`**. *(Included in open Decision #4 for Mokh.)*

| Run Type | VM Phase | Container Extract *(Cached Fixed)* | Prep + Cleanup + Fast Verify | Total Serial / Run | Total Pipelined *(Extract runs during next VM boot)* |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **`executed` attempt** (`120s` dwell + `8s` `inetsim`) | `218s` | `25s` | `7s` | **`250s` (`4.17 min`)** | **`225s` (`3.75 min`)** |
| **`dormant` (`1` sample/boot, `40s` verify/flush)** | `110s` | `25s` | `7s` | **`142s` (`2.37 min`)** | **`117s` (`1.95 min`)** |
| **`dormant` batch (`15–20` samples/overlay, `50s` stage)** | `120s` | `30s` | `10s` | **`160s` (`2.67 min` / `8–10s`/sample)** | **`130s` (`2.17 min`)** |
| **`benign`-only run (`90s` real app/script workload)** | `160s` | `25s` | `7s` | **`192s` (`3.20 min`)** | **`167s` (`2.78 min`)** |

### 2.2 `executed`-First Gating + Hybrid Dormant Staging Strategy
1. **Run `executed` First:** If a sample fails detonation (`0` Sysmon events, corrupted archive, instant crash with `0` artifacts), **never waste a `dormant` run on it**. At `50%` usable yield (`~2,000` executed attempts -> `1,000` usable samples), this immediately cuts dormant work in half (`2,000` -> `1,000` usable samples).
2. **1-Sample-per-Boot vs. Batch-Staged Dormant Comparison (`1,000` Usable Samples):**
   - **Pure 1-Sample-per-Boot Dormant (`1,000` boots × `142s`):** `39.4 hours` VM/extract time.
   - **Pure Batch-Staged Dormant (`20`/overlay -> `50` boots × `160s`):** `2.2 hours`, *but* multi-sample contamination on blind-test overlays mixes `20` malware files onto one host disk (unrealistic blind-test natural prevalence and multi-sample ranking interference).
   - **Recommended Hybrid Architecture:**
     - **Dev (`800` dormant samples):** Batch-stage `16` family-consistent or random dev samples per clean overlay -> **`50` overlays × `160s` = `2.22 hours`**! Then emit each dev dormant sample cleanly against the canonical base record (`artifact_key` non-collision enforced across the 16 staged filenames) for `dev_dedup` and virtual `run_id` LTR queries.
     - **Blind Test (`200` dormant samples):** **Strictly `1` sample per boot (`200` boots × `142s` = `7.89 hours`)** — guaranteeing 100% realistic single-patient natural prevalence (`1` positive per `~4,414` rows) on every blind-test host!
     - **Hybrid Total Dormant Time:** **`10.1 hours` serial** (**saves `29.3 hours`** with zero blind-test compromises).

### 2.3 Yield, Storage & Parallelism (24 GB RAM / 23 GiB Usable Analysis)
- **Usable-Sample Yield:** Target anchor **`50%`** usable rate (`>= 1` attributed post-detonation artifact + verified staging) -> **`~2,000` executed attempts** for `1,000` usable samples (`40%–60%` sensitivity band = `1,667–2,500` attempts). Empirical yield is calibrated first during the Stage A pilot (`6–8` families) before launching Stage B.
- **Storage Budget (`800 GB` Free on `/var` & `/home/fsociety`):**
  - Permanent bases (`win11_base.qcow2` `15.7 GiB` + `inetsim_base.qcow2` `862 MB` + `win11_base_cache.json.gz` `5.3 MB`): **`~16.6 GiB`**.
  - Transient CoW overlay (`~253 MB`/run, **deleted immediately after verified extraction + Parquet/JSONL write**): **`< 1.0 GiB` peak** (even for 2 lanes + NVRAM).
  - Extracted gzip/zstd JSONL run outputs (`~2,450` runs × `~550 KB` compressed): **`~1.4–2.0 GiB`**.
  - Encrypted vault archives (`~2,000` PE zips × `~1.5 MB` avg): **`~3.0 GiB`**.
  - **Total Peak Footprint:** **`< 28 GiB` (`< 3.5%` of `800 GiB` free disk)**.
- **24 GB RAM (`23 GiB` Usable) — 1 Parallel Lane vs. 2 Parallel Lanes:**
  - **Host baseline OS + desktop/libvirt overhead:** `~3.0–4.5 GiB` (even higher if IDE/browser runs simultaneously -> headless `multi-user` or minimal session gives `~19–20 GiB` free for VMs).
  - **1 Lane Architecture (`win11` `4–6 GiB` + `inetsim-vm` `1.0–1.5 GiB` + `--memory=4g` container):**
    - Serial: `~8.5 GiB` total -> **13+ GiB headroom, zero swapping**.
    - **Pipelined (run offline container extraction of Run `i` concurrently while Run `i+1` boots/dwells):** `6` (Win11) + `1.5` (INetSim) + `4` (container) + `3.5` (host) = **`~15.0 GiB` peak** — completely safe, trims `25s/run` -> saves **`~17 hours`** over 2,450 runs with **zero extra Gate 0 firewall risk**.
  - **2 Parallel Lanes Architecture (`win11-a` + `inetsim-a` on `virbr1`, `win11-b` + `inetsim-b` on `virbr2`):**
    - Requires capping each `win11` guest to `4 GiB` RAM + `4` vCPU, each `inetsim-vm` to `768 MiB–1 GiB` RAM, and **serializing** the `--memory=4g` container extractor behind a host lock: `2×4 + 2×1 + 4 + 3.5` = **`~17.5 GiB` peak** (`5.5 GiB` margin — tight; if `win11` stays at `6 GiB`, peak hits `21.5–23.5 GiB` -> triggers swap thrashing on slow boots!).
    - Real speedup is **`~1.65–1.80×`** (not `2.0×`) due to NVMe/CPU boot contention and serialized extraction, and it requires duplicating firewall/XML/negative-egress `NEG-01..10` checks for `virbr2`.
    - **Recommendation:** Start **1 Lane Pipelined**; optionally enable **2 Lanes** after verifying `win11` boots cleanly at `4 GiB` RAM and passing `NEG-01..10` on `virbr2`.

### 2.4 MalwareBazaar Non-Destructive Family Availability (Post-Exclusion)
Hard-excluding ransomware, wipers, and self-propagating worms still leaves **`5` large, active Windows PE categories** with ample MalwareBazaar family depth (`60+` distinct canonical families routinely available):
- **InfoStealers:** `RedLine`, `LummaC2`/`Lumma`, `AgentTesla`, `Vidar`, `Raccoon`, `Formbook`/`XLoader`, `SnakeKeylogger`, `Lokibot`, `MetaStealer`, `RisePro`, `Stealc`, `Rhadamanthys`, `Aurora`, `PhoenixKeylogger`, `MassLogger`.
- **RATs / Backdoors:** `AsyncRAT`, `RemcosRAT`, `NjRAT`, `QuasarRAT`, `DcRAT`, `VenomRAT`, `NanoCore`, `DarkComet`, `OrcusRAT`, `BitRAT`, `WarzoneRAT` (`AveMaria`), `XWorm` *(exclude self-propagating USB/SMB worm variants; allow RAT-only builds or replace with `PhantomRAT`/`PoisonIvy`)*.
- **Loaders / Droppers:** `SmokeLoader`, `Amadey`, `PrivateLoader`, `GuLoader`, `Bumblebee`, `SystemBC`, `PureCrypter`, `HijackLoader`, `Latrodectus`, `DBatLoader` (`ModiLoader`).
- **Coinminers / Clippers:** `XMRig` (droppers/wrappers), `SilentCryptoMiner`, `ClipBanker`, `LaplasClipper`.
- **Trojanized Installers / Adware-PUA:** NSIS/InnoSetup trojanized droppers, `Neshta`, `Andromeda`/`Gamarue` *(legacy C2-less persistence variants where non-worm)*, `BazarLoader`/`CobaltStrike` beacons *(clean user-space persistence beacons)*.

### 2.5 Three Concrete Scale Tiers

| Parameter | **Tier 1: Minimum Viable** | **Tier 2: Target (Recommended)** | **Tier 3: Stretch** |
| :--- | :--- | :--- | :--- |
| **Usable Real Samples (`dev` / `blind_test`)** | **`400`** (`300` / `100`) | **`1,000`** (`800` / `200`) | **`1,500`** (`1,200` / `300`) |
| **Total Real Families (`Blind Test Families`)** | **`30`** (`15` blind test) | **`50–60`** (**`20–25`** blind test) | **`70–80`** (`25–30` blind test; MalwareBazaar clean non-worm/non-ransomware tail gets scarce past ~65–70) |
| **Benign-Only Runs (`dev` / `blind_test`)** | `100` (`80` / `20`) | `200` (`160` / `40`) | `300` (`240` / `60`) |
| **Executed Attempts @ 50% Yield** *(40–60% band)* | `800` (`667–1,000`) | **`2,000`** (`1,667–2,500`) | `3,000` (`2,500–3,750`) |
| **Dormant Runs (Hybrid: Dev Batched @ 16 + Test 1/boot)** | `19 + 100 = 119` | **`50 + 200 = 250`** | `75 + 300 = 375` |
| **Total VM Boots (Exec + Hybrid Dormant + Benign)** | `~1,019` | **`~2,450`** | `~3,675` |
| **Active Compute Hours — 1 Lane Pipelined** | **`~57 hrs`** | **`~137 hrs`** *(unpipelined `152 hrs`)* | **`~205 hrs`** |
| **Active Compute Hours — 2 Lanes** *(if validated)* | `~34 hrs` | **`~82 hrs`** | `~123 hrs` |
| **Realistic Calendar Timeline** *(@ ~8–10 hrs/day unattended)* | **1 Lane:** `6–8 days`<br>**2 Lanes:** `4–5 days` | **1 Lane:** **`14–18 days`** *(~2.5 wks)*<br>**2 Lanes:** **`9–12 days`** | **1 Lane:** `21–26 days`<br>**2 Lanes:** `13–17 days` |

---

## 3. Split Design, Clustering & Statistical Power

### 3.1 Anti-Leakage Split Invariants
1. **Family + Similarity Union-Find Partitioning:**
   - Canonicalize family labels via AVClass2/ClarAVy-style normalization (`scripts/v2_curate_vault_manifest.py`) before cluster formation.
   - Cluster all usable samples transitively via union-find across: identical `sample_family`, fuzzy similarity (`ssdeep >= 50` or `TLSH distance <= 70` or shared `imphash` within non-generic stub packers), `packer_cluster`, `sample_sha256`, and `pair_group_id`.
   - Every connected component enters **strictly one** side: `dev` or `blind_test`. Both `executed` and `dormant` rows of sample $s$ share `pair_group_id` and remain on the same side.
2. **Per-Family Caps & Category Stratification:**
   - **Minimum Viable (`400`):** cap `<= 25` samples/family in dev, `<= 12` in blind test; `F_test >= 15`.
   - **Target (`1,000`):** cap `<= 30` samples/family in dev, **`<= 15` in blind test**; **`F_test = 20–25` families (`>= 15` hard floor)**, stratified proportionally across all 5 allowed categories (InfoStealer, RAT, Loader, Miner/Clipper, Trojanized Installer).
   - **Stretch (`1,500`):** cap `<= 35` samples/family in dev, `<= 15` in blind test; `F_test = 25–30`.
   - **Pilot Firewall:** Any Stage A pilot family stays strictly inside `dev` (`0%` blind test).
3. **Benign & Emulated Split Rules:**
   - **Disjoint Benign Profiles:** Dev (`160` runs) uses benign software/workload profiles `B_dev_01..B_dev_20` (Git, Python, 7-Zip, Notepad++, Sysinternals, procedural admin scripts, unsigned PEs); Blind Test (`40` runs) uses **disjoint** software/script profiles `B_test_01..B_test_10` (different installers, scheduled tasks, services, unsigned tools, benign system noise).
   - **v1 `emulated`:** Strictly in `dev` (`0%` in blind test).

### 3.2 Statistical Power Analysis per Tier (Family-Clustered Bootstrap)
Because host rows within the same malware family are correlated, effective independent sample size for blind-test model comparison is the number of blind-test family clusters **$F_{\text{test}}$**. For a two-sided paired test at 80% power ($z_{0.80}=0.842$), Minimum Detectable PR-AUC Difference $\text{MDE} \approx (z_{1-\alpha'/2} + 0.842)\,\sigma_{\Delta,\text{family}} / \sqrt{F_{\text{test}}}$:

| Tier ($F_{\text{test}}$) | Bootstrap Atom Floor ($1/F_{\text{test}}$) | Assumed Family Diff SD $\sigma_{\Delta,\text{family}}$ | Unadjusted MDE ($\alpha=0.05$, $z_{\text{sum}}=2.80$) | **Pre-Registered `m=10` Holm Step-1** ($\alpha'=0.005$, $z_{\text{sum}}=3.65$) | Naive `153`-Pair Holm Step-1 ($\alpha'=0.00033$, $z_{\text{sum}}=4.43$) *(Avoid!)* |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Min Viable ($F_{\text{test}}=15$)** | $6.7\%$ | `0.06` / `0.08` / `0.10` | `0.043` / `0.058` / `0.072` | `0.057` / `0.075` / `0.094` | `0.069` / `0.092` / `0.114` *(severe power collapse)* |
| **Target ($F_{\text{test}}=22$)** | $4.5\%$ | `0.06` / `0.08` / `0.10` | `0.036` / `0.048` / `0.060` | **`0.047` / `0.062` / `0.078`** | `0.057` / `0.076` / `0.094` |
| **Target High ($F_{\text{test}}=25$)** | $4.0\%$ | `0.06` / `0.08` / `0.10` | `0.034` / `0.045` / `0.056` | **`0.044` / `0.058` / `0.073`** | `0.053` / `0.071` / `0.089` |
| **Stretch ($F_{\text{test}}=30$)** | $3.3\%$ | `0.06` / `0.08` / `0.10` | `0.031` / `0.041` / `0.051` | `0.040` / `0.053` / `0.067` | `0.049` / `0.065` / `0.081` |

*(Empirical $\sigma_{\Delta,\text{family}}$ is calibrated directly on Stage A pilot LOFO output via `compute_empirical_family_power_table` before freezing `FINAL_EVAL_PLAN_v2.md`.)*

---

## 4. Impact Analysis (`KEEP` / `CHANGE` / `DESCOPE`)

*(Full per-item matrix across `OD-V2-01..20`, all 13 `src/v2/` modules, `scripts/`, and all 10 `tests/test_v2_*.py` files is below; see also [`PIVOT_CODEBASE_AUDIT.md`](PIVOT_CODEBASE_AUDIT.md).)*

### 4.1 Operator Decisions (`OD-V2-01..20`)

| ID | Topic | Action | Revised Scope Under Comparative Study Pivot |
| :---: | :--- | :---: | :--- |
| **`OD-V2-01`** | Data targets | **`CHANGE`** | Upgrade target from `~300–500` positives / `100+` runs to **Target Tier: `1,000` usable samples (`800` dev / `200` test) across `50–60` families (`20–25` blind test) + `200` benign runs (`160`/`40`)**, calibrated by Stage A pilot yield |
| **`OD-V2-02`** | v1 reuse (`emulated`) & F0 parity | **`KEEP`** | Frozen `dataset_v1.parquet` (`1,104` cold-disk dev rows) stays strictly `dev`-only `"emulated"` stratum (`0%` blind test); cited only as initial baseline motivating v2 |
| **`OD-V2-03`** | Separate `inetsim-vm` | **`KEEP`** | Unchanged (`192.168.150.10` on `win11-isolated`) |
| **`OD-V2-04`** | Offline container extraction | **`KEEP`** | Unchanged (`--network=none --read-only --cap-drop=ALL`) + rebuild `win11_base_cache.json.gz` for `128 MiB` speedup (`~20s`) |
| **`OD-V2-05`** | Stage A pilot scope | **`CHANGE`** | Keep `~3` clean controls + `6–8` non-test families × paired `dormant`/`executed` to measure yield & power; **drop `OD-V2-20` refgraph gating** and validate canary safety gate |
| **`OD-V2-06`** | Seeds & tuning budget | **`CHANGE`** | Keep `K=5` seeds (`[42..46]`); enforce **`20` EQUAL trials across ALL tuned models** (Tier A, Tier B CUDA, and Tier C capped instance) inside **`5`-fold outer × `3`-fold inner** family-grouped CV (`15` fits/trial) to eliminate `IMP-09` unequal-budget bias; fit calibrators/1%-FPR thresholds strictly on natural-prevalence dev OOF (or exact dev-only Bayes prior-odds adjustment) |
| **`OD-V2-07`** | Vault & Supervisor approval | **`LOCKED`** | **Supervisor Marawan (AASTMT) granted approval on `2026-11-25`** for Tier 2 Target (`1,000` usable / `~2,000+` attempts + `200` benign runs, Tier 1 `400` usable Checkpoint 1) under strict ransomware/wiper/worm exclusion and resolution of all 6 audited safety items (`05_quarantine_vault_setup.sh` `0400` gate, runnable `.exe` gate, detached watchdog, exception-safe base verify, `virbr1` packet-counter egress audit, `--canary` smoke gate) |
| **`OD-V2-08`** | Malware categories & normalization | **`CHANGE`** | **Remove `Ransomware`**; enforce hard-exclude blocklist for **ransomware, wipers, and worms**; keep InfoStealers, RATs/Backdoors, Loaders/Droppers, Coinminers/Clippers, Trojanized Installers + AVClass2/`ssdeep`/TLSH/imphash clustering |
| **`OD-V2-09`** | Stratum mix (`executed`/`dormant`/`emulated`) | **`CHANGE`** | Keep paired `executed` + `dormant` evaluation for **100% of usable samples** (not 60/40 subset); add dev batched dormant (`16`/overlay) while keeping blind test 100% `1`-sample-per-boot |
| **`OD-V2-10`** | Blinded human review ownership | **`CHANGE`** | Keep friend primary + Mokh `20%` overlap $\kappa$, **capped at stratified `400`-row sample (`80` overlap)** by fixing unbounded positives in `review_v2.py:85` |
| **`OD-V2-11`** | Feature schema scope | **`CHANGE`** | Keep locked `full_20` + `no_content` as the primary comparative study schemas; **drop `v2_refgraph` arm** (and ensure `eval`/`export` never leaks `FORBIDDEN_MODEL_INPUTS`) |
| **`OD-V2-12`** | Benign roster & prevalence policy | **`CHANGE`** | Disjoint dev/test benign profiles across `200` runs; explicitly specify **train-time OS-baseline deduplication in dev** vs. **100% natural per-host prevalence in blind test** (+ subsampled secondary view) |
| **`OD-V2-13`** | `v2_refgraph` secondary arm | **`DESCOPE`** | Removed from v2 core scope |
| **`OD-V2-14`** | Tail-risk & effort metrics | **`KEEP`** | Integral part of the comparative model scorecard (`worst_positive_rank`, `Recall@k`, `Effort@Recall`, bottom `50%/90%`) |
| **`OD-V2-15`** | Execution Delta / Evasion contrast | **`CHANGE`** | Keep **executed vs. dormant purely as a plain descriptive table** per model + robustness ablations (`drop_signature`, `no_content`, `no_content_no_sig`); remove Concept C novelty framing |
| **`OD-V2-16`** | Offline pointer capture (`offline_extractor.py`) | **`KEEP (FROZEN)`** | Keep existing pointer capture untouched inside `offline_extractor.py` so existing extractor & parity tests pass; no new graph parsing work |
| **`OD-V2-17`** | 3 refgraph propagation baselines | **`DESCOPE`** | Out of v2 core scope |
| **`OD-V2-18`** | Heterogeneous GNNs (`R-GCN`/`GAT`) | **`DESCOPE`** | Remains excluded |
| **`OD-V2-19`** | Post-final stretch items | **`KEEP (DEFERRED)`** | Remains strictly post-`--final` / future work (including `REVENANT` live demo & dashboard post-freeze) |
| **`OD-V2-20`** | `v2_refgraph` 50% pilot gate | **`DESCOPE`** | Dropped alongside `v2_refgraph` |

### 4.2 Modules, Scripts & Hardening Assets

| File / Asset | Action | Rationale & Specific Change |
| :--- | :---: | :--- |
| [`src/v2/refgraph.py`](../../src/v2/refgraph.py), [`refgraph_audit.py`](../../src/v2/refgraph_audit.py) | **`DESCOPE (FREEZE)`** | Keep intact & passing unit tests so nothing breaks; zero new work or paper claims |
| [`src/v2/offline_extractor.py`](../../src/v2/offline_extractor.py) | **`DONE (SPRINT 1)`** | Pointer capture stays frozen untouched (`4,414` rows verified); added atomic `save_base_image_cache`, `--patch-stale-large-pe-cache` (`128 MiB` patcher), and read-only `sysmon_events.jsonl` EVTX export |
| [`src/v2/pilot_staging.py`](../../src/v2/pilot_staging.py) | **`DONE (SPRINT 1)`** | Hard ransomware/wiper/worm blocklist inside `validate_stage_run_spec`, zero-rebake dev-only `dormant_batch` ISO mode, and real `benign_generator_v2` integration |
| [`src/v2/run_stage_a_pilot.py`](../../src/v2/run_stage_a_pilot.py) | **`DONE (SPRINT 1)`** | Detached host watchdog (armed *before* `virsh start`), `finally:` fast/periodic base-hash + `virbr1` packet-counter assertions, `--canary` smoke gate, `--pipelined` overlay support, and `completed_runs.jsonl` resume |
| [`src/v2/labeler_v2.py`](../../src/v2/labeler_v2.py) | **`DONE (SPRINT 1)`** | Preserved multi-control + Sysmon causality; added `benign_manifest` attribution, `label_dormant_batch_run` (`dev`-only), and `deduplicate_dev_os_baseline` |
| [`src/v2/review_v2.py`](../../src/v2/review_v2.py) | **`DONE (SPRINT 1)`** | Capped stratified blinded export (`400` primary rows: `200` pos / `100` drift / `100` ambiguous; `80` / `20%` overlap slice) |
| [`src/v2/config_v2.py`](../../src/v2/config_v2.py) | **`DONE (SPRINT 1) + SPRINT 2`** | Sprint 1 locked `V2_N_SEARCH_TRIALS = 20` & `V2_INNER_FOLDS = 3` (`5×3` nested CV, `20` equal trials); Sprint 2 expands to full ~20-model registry, calibration configs, and comparative pre-registered pairs |
| [`src/v2/models_v2.py`](../../src/v2/models_v2.py) | **`SPRINT 2`** | Add `LinearSVC`, `NystroemRBF`, `KNeighbors`, `DecisionTree`, `ExtraTrees`, `HistGBDT`, `LightGBM`, `CatBoost`, `XGBRanker`, `LGBMRanker`, `FTTransformer`/`ResNetTabular`, `NystroemOCSVM`, `LOF`, `RuleMLHybrid`, optional `TabPFN` |
| [`src/v2/training.py`](../../src/v2/training.py) | **`SPRINT 2`** | Wire fold-local train-time OS-baseline deduplication, per-`run_id` LTR query-group batcher, natural-prevalence dev OOF / Bayes prior-odds calibration, learning-curve trainer, inference/SHAP timer, and `run_nested_family_cv` (`20` equal trials, `5×3`) across Tier A/B/C |
| [`src/v2/stats_v2.py`](../../src/v2/stats_v2.py) | **`SPRINT 2`** | Add **Friedman + Nemenyi** omnibus/CD rank test, `m=10` paradigm-representative confirmatory Holm-Bonferroni family (`evaluate_fixed_comparisons_dual_config`), calibration (`ECE`/Brier) metrics, clean-host FP/run metrics, and 5-axis decision scorecard |
| [`src/v2/ablations_v2.py`](../../src/v2/ablations_v2.py) | **`KEEP / SPRINT 2`** | Keep dev-only guard & config-matched tuning (`drop_signature`, `no_content_no_sig`, feature-group drops); wire new model arms and `H1`–`H3` transfer experiments |
| [`scripts/v2_curate_vault_manifest.py`](../../scripts/v2_curate_vault_manifest.py) | **`DONE (SPRINT 1)`** | Removed `ransomware` tags & `"ransom"` boost, enforced hard-deny blocklist (ransomware/wiper/worm) + standalone runnable `.exe` `pefile` gate, `50–60` family quotas (`~2,000` archives), `ssdeep`/`tlsh`/`imphash` clusters |
| [`scripts/compare_v1_v2_parity.py`](../../scripts/compare_v1_v2_parity.py), [`verify_stratified_shortcuts.py`](../../scripts/verify_stratified_shortcuts.py) | **`KEEP`** | No changes needed |
| [`scripts/v2_prepare_benign_pools.py`](../../scripts/v2_prepare_benign_pools.py), [`src/v2/benign_generator_v2.py`](../../src/v2/benign_generator_v2.py) | **`NEW (SPRINT 1)`** | Disjoint `dev` vs `blind_test` benign software/archive pools + non-quantized benign generator (`1,500–2,000` unique drift files + `200–400` benign persistence entries) |
| [`docs/v2/hardening/04_watchdog_and_base_hash.sh`](hardening/04_watchdog_and_base_hash.sh), [`05_quarantine_vault_setup.sh`](hardening/05_quarantine_vault_setup.sh), [`06_unprivileged_container_runner.sh`](hardening/06_unprivileged_container_runner.sh) | **`DONE (SPRINT 1)`** | Detached host watchdog covering `win11`+`inetsim-vm`, fast+periodic base verification, `virbr1` counter snapshot/check helper (`04`); strict `GATE0_SIGNED_OFF` `0400` + 5-field & manifest enforcement (`05`); per-overlay `domblklist` extraction check (`06`) |
| `docs/v2/hardening/{01,02,03,07,check_domain_xml,Install-V2BaseBootstrap}` | **`KEEP`** | Zero edits to sealed VM/firewall/bridge XML hardening (`1` pipelined lane on `virbr1`) |
| **New Modules (`src/api/`, `src/web/`)** *(Sprint 2 / Post-Stage A)* | **`DEFERRED TO SPRINT 2`** | Model-agnostic `ScorerAdapter`, SHAP value bug fix (reusing `export_findings.py`), FastAPI endpoints, offline Linux results reader + separate clean demo endpoint & analyst dashboard |

### 4.3 Test Coverage Plan (`tests/test_v2_*.py`)
- **Stay Untouched & Green (`3` files):** `test_v2_refgraph.py`, `test_v2_refgraph_audit.py`, `test_v2_schema.py`.
- **Sprint 1 Updated (`6` files):**
  1. `test_v2_parity_and_pilot.py`: valid `0400` `GATE0_SIGNED_OFF`, runnable `.exe` PE fixtures, allowed families (`redline`/`asyncrat`/`smokeloader`/`xmrig`/`amadey`/`lummac2`), ransomware/wiper/worm hard-deny blocklist, `IMAGE_FILE_DLL` rejection, dev-only `dormant_batch`, detached watchdog, `finally:` base-hash + egress check, `--canary`, `--pipelined`, and resume.
  2. `test_v2_hardening_validators.py`: strict `GATE0_SIGNED_OFF` `0400`/field/manifest checks, `verify-base-fast` stat drift, detached watchdog timeout/`disarm-watchdog`, `virbr1` `check-egress` delta, and `06_unprivileged_container_runner.sh` per-overlay `domblklist` check.
  3. `test_v2_offline_extractor.py`: `patch_stale_large_pe_cache` atomic update + `normalize_sysmon_evtx_record` + `sysmon_events.jsonl` export.
  4. `test_v2_labeler_and_review.py`: dev-only OS-baseline deduplication, dev-only `label_dormant_batch_run`, and stratified `400`/`80` `review_v2.export_blinded_review_sample`.
  5. `test_v2_shortcut_audit.py`: real non-quantized `benign_generator_v2` rows + `v2_prepare_benign_pools` cross-split collision rejection.
  6. `test_v2_training.py` (partial Sprint 1 budget check): `V2_N_SEARCH_TRIALS == 20`, `V2_INNER_FOLDS == 3` (`20` equal trials).
- **Sprint 2 Expansion (`2` files):**
  1. `test_v2_training.py`: new model wrappers (`LightGBM`, `CatBoost`, `XGBRanker`/`LGBMRanker`, deep tabular, `Nystroem` kernels, capped `kNN`/`LOF`), fold-local deduplication, natural-prevalence calibration, and `H1`–`H3` train-stratum pipelines.
  2. `test_v2_stats_and_ablations.py`: Friedman/Nemenyi ranker, `m=10` confirmatory Holm table, calibration (`ECE`/Brier), and 5-axis decision scorecard.

---

## 5. Expanded Model Comparison Design (No Pre-Selected Winner)

### 5.1 Complete Comparative Model Registry (~21 Evaluated Arms + 1 Optional Capped Arm)

| Paradigm Family | Model Arm (`key`) | Scaling & Constraints (`dev_dedup ~80k` / `test ~1.96M`) | Equal Tuning Budget |
| :--- | :--- | :--- | :--- |
| **Linear & Kernel / Instance** | 1. Logistic Regression (`lr`) | $O(N \cdot d)$, L2/L1, `class_weight` | Tier A (**20 trials**) |
| | 2. Linear SVC + Platt (`linear_svc`) | $O(N \cdot d)$ + calibrated inner-OOF sigmoid | Tier A (**20 trials**) |
| | 3. RBF Kernel Approx. (`nystroem_rbf`) | **Mitigates exact $O(N^2\text{--}N^3)$ RBF-SVM**: `Nystroem(n_components in {500,1000,1500}) + LR` | Tier A (**20 trials**) |
| | 4. k-Nearest Neighbors (`knn_capped`) | **Mitigates $O(N^2)$ over `1.96M` test**: deterministic stratified `N_index = 15,000` dev reference | Tier C (**20 trials**) |
| **Classical & Boosted Trees** | 5. Decision Tree (`dt`) | Interpretable single-tree baseline | Tier A (**20 trials**) |
| | 6. Random Forest (`rf`) | Multi-core CPU bagging (`n_jobs=-1`) | Tier A (**20 trials**) |
| | 7. Extra Trees (`et`) | Random-split variance-reduced ensemble | Tier A (**20 trials**) |
| | 8. HistGradientBoosting (`histgbdt`) | Native sklearn histogram boosting | Tier A (**20 trials**) |
| | 9. XGBoost (`xgb`) | `hist` GBDT + `scale_pos_weight` (`xgboost==3.4.1`) | Tier A (**20 trials**) |
| | 10. LightGBM (`lgbm`) | Leaf-wise histogram GBDT (`lightgbm`) | Tier A (**20 trials**) |
| | 11. CatBoost (`catboost`) | Symmetric oblivious trees (`catboost`) | Tier A (**20 trials**) |
| **Learning-to-Rank (Host-Grouped)** | 12. XGBoost Ranker (`xgb_ranker`) | `rank:ndcg` / `rank:pairwise` grouped strictly by `qid=run_id` (`dev_ltr` `~400k`) | Tier A (**20 trials**) |
| | 13. LightGBM Ranker (`lgbm_ranker`) | `lambdarank` grouped strictly by `qid=run_id` (`dev_ltr` `~400k`) | Tier A (**20 trials**) |
| **Neural / Deep Tabular (RTX 2050 CUDA)** | 14. Tabular MLP (`mlp`) | `BatchNorm`/`LayerNorm` + dropout + early stopping | Tier B (**20 trials**) |
| | 15. FT-Transformer or ResNet-Tabular (`ft_transformer` / `resnet_tabular`) | Feature tokenization / residual tabular blocks on CUDA (`4 GiB` VRAM) | Tier B (**20 trials**) |
| | *Optional:* TabPFN (`tabpfn_10k`) | **Hard `<= 10,000`-row training cap**; strictly optional/exploratory reference arm (skip if HF/weights block install) | Tier 0 (**0 trials**) |
| **Unsupervised / One-Class** *(Strict `y == 0` benign fit)* | 16. Isolation Forest (`iforest`) | Label-free & label-selected validation (`score_unsupervised_label_free`) | Tier A (**20 trials**) |
| | 17. Deep Autoencoder (`ae`) | Symmetric CUDA MSE reconstruction scorer | Tier B (**20 trials**) |
| | 18. RBF One-Class SVM Approx. (`nystroem_ocsvm`) | **Mitigates exact $O(N^2\text{--}N^3)$ OC-SVM**: `Nystroem + SGDOneClassSVM` on full benign pool | Tier A (**20 trials**) |
| | 19. Local Outlier Factor (`lof_capped`) | **Mitigates $O(N^2)$ query**: `novelty=True` on stratified `15,000`-row benign reference | Tier C (**20 trials**) |
| **Baselines & Hybrid** | 20. Deterministic Rules (`rules_binary`, `rules_count`) | `src/rules/deterministic_rules.py` (`RULE-001..015`) | Tier 0 (**0 trials**) |
| | 21. Monte Carlo Random (`mc_random`) | `10,000` finite-sample permutations (`stats_v2.py:77`) | Tier 0 (**0 trials**) |
| | 22. Rule + Top-ML Hybrid (`rule_ml_hybrid`) | Lexicographic boost (`rule_hit_count > 0` prioritized via dev-tuned weight $\lambda$ + calibrated ML lead rank) | Dev OOF 1D grid |

### 5.2 Equal-Budget Tuning Protocol & ASUS Laptop Compute Estimate (`20` Equal Trials, `5×3` Nested CV)
All tuned models (Tier A trees/linear/LTR, Tier B CUDA deep tabular, and Tier C capped instance) receive the **exact same `20`-trial Optuna/random search budget** inside `5` outer × `3` inner family-grouped CV (`15` fits per trial = `300` fits per arm per feature config) so no paradigm gains an unfair tuning advantage (`IMP-09` elimination):

- **Nested CV per tuned arm (`5` outer × `3` inner folds across `full_20` + `no_content`):**
  - **Tier A (`14` arms × `20` trials × `15` CV fits × `2` configs = `8,400` fast CPU fits):** Avg `~2.2s/fit` on Ryzen 7 7435HS (`16` threads) -> **`~5.1 hours`** (`xgboost`, `lightgbm`, `catboost`, `rf`, `et`, `dt`, `lr`, `svc`, `nystroem`, `iforest`).
  - **Tier B (`3` CUDA neural arms: `mlp`, `ae`, `ft_transformer` × `20` trials × `15` CV fits × `2` configs = `1,800` RTX 2050 fits):** Avg `~12s/fit` -> **`~6.0 hours`**.
  - **Tier C (`2` capped instance arms × `20` trials × `15` CV fits × `2` configs = `1,200` capped-ref fits):** `~0.4 hours`.
- **Post-CV Evaluation (`K=5` final seeds `[42..46]`, natural-prevalence dev OOF / Bayes prior-odds calibration, learning curves at `{10%, 25%, 50%, 100%}` of dev families, ablations `drop_signature` & `no_content_no_sig`, LOFO, `1.96M`-row blind inference + top-25 SHAP latency profiling):** **`~3.5–5.0 hours`**.
- **Total End-to-End Benchmark Compute:** **`~15.0–16.5 hours`** — comfortably runs in **2 overnight ASUS sessions**.

### 5.3 Evaluation Axes, Multiple-Comparison Control & Decision Rule
- **Comprehensive Evaluation Metrics:**
  - *Primary Discrimination:* Blind-test `PR-AUC` (pooled & per-host macro) across `full_20` & `no_content`.
  - *Operational Triage & Tail Risk:* `Recall@{10, 20, 50}`, `Precision@{10, 50}`, `Effort@Recall(50%, 80%, 90%)`, `worst_positive_rank`, `IntrusionRecall@k` (fraction of infected hosts caught in top-k), and clean-host false alerts/run at dev-calibrated `1%` & `5%` FPR thresholds.
  - *Reliability & Efficiency:* Learning curves (`10%`, `25%`, `50%`, `100%` dev families), Calibration (`ECE`, Brier score, reliability plots + Platt/Isotonic fitted strictly on **natural-prevalence dev OOF or exact dev-only Bayes prior-odds adjustment**, never raw `dev_dedup` `~7%` prevalence), Evasion ablations (`drop_signature`, `no_content`, `no_content_no_sig`), LOFO per-family floor (`min` & `IQR` PR-AUC across blind families), `K=5` seed std, and CPU/GPU per-host (`4,414`-row) inference + top-25 SHAP explanation latency.
- **Multiple-Comparison Control (Avoiding 136-Pair Holm-Bonferroni Collapse):**
  - Testing all $\binom{18}{2}=153$ pairs via Holm-Bonferroni inflates $\alpha' = 0.05/153 = 0.00033$, destroying statistical power at $F_{\text{test}}=20\text{--}25$. Instead use a **two-stage hierarchical protocol:**
  - **Stage 1 (Global Omnibus Across All ~20 Models):** Non-parametric **Friedman test ($\alpha=0.05$) + post-hoc Nemenyi Critical-Difference (CD) diagram** over blind-test family-level `AP` (`F_test` independent families).
  - **Stage 2 (Pre-Registered Confirmatory Family — `m = 10` Fixed Contrasts):** Before unblinding the test set, select **1 dev-OOF top model per paradigm** (`top_gbdt`, `top_ltr`, `top_bagging`, `top_deep`, `top_linear`, `top_unsup`) plus fixed anchors (`xgb`, `rules_count`, `rule_ml_hybrid`), yielding **`m = 10` pre-registered pairwise contrasts** tested with family-clustered paired bootstrap ($B=2,000$) + step-down Holm-Bonferroni across both `full_20` and `no_content`.
- **Pre-Registered 5-Axis Model Selection Rule (No Winner Pre-Judged):**
  - *Hard Disqualification Gates:* **(1)** Fails `rules_count` OR `mc_random` on either `full_20` or `no_content`, OR **(2)** per-host inference + top-25 SHAP latency exceeds **`5.0s / host`** on CPU.
  - *Weighted Composite Rank Score (computed on blind-test normalized scores after Stage 2 significance check):*
    1. **Discrimination (`35%`):** Pooled & per-host PR-AUC averaged equally across `full_20` (`17.5%`) and `no_content` (`17.5%`).
    2. **Operational Effort & Tail Risk (`25%`):** `Effort@Recall(80%)` (`10%`), `IntrusionRecall@20` (`10%`), Clean-host FPs/host @ `1%` dev FPR (`5%`).
    3. **Evasion Resilience (`15%`):** Mean `drop_signature` & `no_content_no_sig` PR-AUC retention.
    4. **Stability, Generalization & Calibration (`15%`):** LOFO bottom-quartile family PR-AUC (`5%`), `K=5` seed IQR (`5%`), ECE (`5%`).
    5. **Deployment Latency (`10%`):** Measured CPU per-host score + top-25 SHAP runtime.
  - *Tie-Breaker:* If the top two paradigm winners are `"not distinguishable"` ($p_{\text{adj}} \ge 0.05$) and within `0.015` composite points, prefer lower inference latency and lower `no_content_no_sig` variance. **No winner is assumed prior to empirical execution.**

---

## 6. Pre-Registered Falsifiable Hypotheses

| ID | Pre-Registered Claim | Protocol & Metric | Supported If | **Falsified / Contradicted If** |
| :---: | :--- | :--- | :--- | :--- |
| **H1** | **Split-Leakage Sensitivity:** Naive random row splits artificially inflate DFIR triage performance relative to leakage-free family- + `ssdeep`/TLSH-grouped splits. | Train identical `dev_dedup` models under random row split vs. family-grouped split (`5` seeds), tested on unseen blind families. | Random-split CV overestimates true blind-test PR-AUC by `>= +0.05` (with disjoint family-clustered 95% CIs) due to sample/family memorization. | Gap between random-split and family-grouped blind-test PR-AUC is `< 0.02` OR non-significant / reversed. |
| **H2** | **Provenance-Label Trust & Contamination:** Heuristic/noisy labels vs. strict Sysmon + multi-control provenance (isolating `ambiguous_unattributed`) meaningfully affects model ranking and generalization. | Compare models trained/evaluated on strict provenance labels (`labeler_v2`) vs. heuristic timestamp-window/rule-derived pseudo-labels on blind test (anchored by blinded human-review $\kappa$). | Provenance-trained models outperform pseudo-label-trained models on blinded human-verified ground truth (`PR-AUC`, lower `ECE`) AND blinded human inter-rater $\kappa \ge 0.70$. | Heuristic pseudo-label models match or beat provenance models ($\Delta\text{PR-AUC} \le 0.01$) OR blinded human review $\kappa < 0.60$. |
| **H3** | **Emulated vs. Real Transfer:** Training solely on v1-style `emulated` telemetry transfers poorly to unseen real malware hosts, whereas `real`-only or `mixed` training generalizes significantly better *(including a size-matched control subsampling real dev to match `v1` row/positive counts)*. | Train **3 arms + 1 size-matched control** (`emulated-only`, `real-matched`, `real-full`, `mixed`) tested on the identical unseen `real` blind test (`full_20` & `no_content`). | `real-matched` and `real-full` significantly beat `emulated-only` ($p_{\text{adj}} < 0.05$) on unseen real malware hosts, and `mixed` is neutral or beneficial without degrading `no_content`. | `emulated-only` matches `real-matched` ($\Delta \le 0.02$, $p \ge 0.05$) on blind real malware — contradicting the core thesis that self-generated real Win11 collection was necessary! |
| **H4** | **Decisive Paradigm Separation:** Across ~20 architectures evaluated on `full_20` & `no_content` natural prevalence, modern tabular learners (GBDT/LTR/Deep Tabular) dominate linear, classical instance/one-class, and deterministic rule baselines on operational triage effort. | Friedman + Nemenyi CD + `m=10` Holm-Bonferroni contrasts + 5-axis scorecard on blind test. | Rejects Friedman null ($p < 0.05$) with clear Nemenyi separation and dual-config statistically significant superiority over `rules_count` & linear baselines. | Friedman omnibus fails to reject null ($p \ge 0.05$), or no ML paradigm achieves dual-config superiority over `rules_count` + `lr`. |

*(Cross-stratum `executed` vs. `dormant` performance across models is reported purely as a **plain descriptive comparison table** showing natural differences in detectability and signature dependence, with zero novelty hypothesis attached.)*

---

## 7. Results-Screen & Model-Agnostic API Design (Research + Safe Demo Separation)

### 7.1 Hard Air-Gap & Network Separation Rule
- **Non-Negotiable Containment Rule:** **NO malware-detonated VM (`win11` on `win11-isolated` / `virbr1`) may EVER have a network or host channel to the Linux host API, filesystem, or web server.** During research/dataset evaluation, artifacts flow **strictly one-way** through the offline unprivileged container ([`06_unprivileged_container_runner.sh`](hardening/06_unprivileged_container_runner.sh)) into Linux Parquet/JSONL stores read offline by the Linux API.
- **Two Strict Deployment Modes:**
  1. **Offline Research / Evidence Reader Mode (Default):** FastAPI reads immutable extracted JSONL/Parquet host bundles directly on the Linux workstation (`POST /api/v1/triage/import-offline`), executes deterministic rules + any winning v2 `ScorerAdapter`, and serves the local Web UI (`127.0.0.1` only).
  2. **Controlled Live Triage Demo Mode (Isolated `win11-demo` Network Only):** Uses a **separate clean or strictly emulated (non-malware) VM `win11-demo`** attached to a **separate libvirt bridge `win11-demo-net` (`192.168.160.0/24`)** allowed *only* to connect via HTTPS/TLS + bearer token/mTLS to Linux API port `8443` — completely disjoint from `win11` and `win11-isolated` (`virbr1`).

```text
[RESEARCH / MALWARE POOL]                          [SEPARATE CLEAN DEMO POOL ONLY]
  win11 (malware) <--L2--> inetsim-vm                win11-demo (clean/benign/Atomic demo)
        | (virbr1: ALL host/WAN DROP)                      | (win11-demo-net: 192.168.160.0/24)
        v  [virsh destroy -> RO overlay]                   v  TLS + X-API-Key POST /api/v1/triage/submit
[Unprivileged Container Extractor]                 +---------------------------------------------+
        |  Offline JSONL / Parquet  -------------> | Linux FastAPI Triage Backend (127.0.0.1 /   |
                                                   | 192.168.160.1:8443) + ScorerAdapter         |
                                                   +----------------------+----------------------+
                                                                          | (Localhost Only)
                                                                          v
                                                   [DFIR Analyst Results Screen (React / HTML)]
```

### 7.2 Model-Agnostic `ScorerAdapter` & SHAP Fix
- Every candidate winner exports a uniform **Versioned Bundle** (`model_bundle/<arm_id>/`): `preprocessor.joblib`, model weights (`xgb.ubj`/`lgbm.txt`/`catboost.cbm`/`pt` weights), `calibrator.joblib`, `adapter_meta.json` (`arm`, `feature_schema`, `dev_threshold_1pct_fpr`, `shap_explainer_type`).
- A unified Python protocol **`ScorerAdapter`** exposes:
  - `score_batch(df_raw) -> tuple[np.ndarray, pd.DataFrame]` *(computes & attaches `F.row_features(row)` directly onto `df_feat` — **fixing the v1 `export_findings.py:105` `"feature_value": null` bug!**)*
  - `explain_top_leads(df_feat, top_n_leads=50) -> list[dict]` *(runs `TreeExplainer`, `LinearExplainer`, or `GradientExplainer`/background KernelSHAP depending on `arm` and maps top SHAP drivers into plain-English analyst reasons — e.g., `"Unsigned executable in AppData path (+0.21)"` rather than `"file_size_log: null"`).*

### 7.3 REST API Contract & Security Controls
- **Auth & Input Hardening:** `X-API-Key` + optional mTLS for demo NIC; `<= 25 MB` gzip payload cap; Pydantic strict schema validation (rejecting unexpected fields/null bytes); per-IP rate limiting; immutable append-only `case_audit.jsonl`.
- **Endpoints:**
  - `POST /api/v1/triage/import-offline` *(Linux local offline bundle loader)*
  - `POST /api/v1/triage/submit` *(Demo-mode JSON/collector payload ingestion)*
  - `GET /api/v1/cases` & `GET /api/v1/cases/{case_id}/summary` *(Host risk posture, total scanned artifacts, model bundle ID, calibrated alert count)*
  - `GET /api/v1/cases/{case_id}/findings` *(Strict Layer 1 deterministic rule hits `F-xxxx`, ATT&CK ID, severity, IOCs, ordered by ML score)*
  - `GET /api/v1/cases/{case_id}/leads` *(Strict Layer 2 unruled ML leads `L-xxxx`, `technique_id: null`, calibrated score + percentile, plain-English SHAP drivers, artifact provenance)*
  - `POST /api/v1/cases/{case_id}/items/{item_id}/decision` *(Layer 4 analyst disposition: `confirm_malicious` / `benign_false_positive` / `needs_deeper_ir` + rationale)*
  - `GET /api/v1/cases/{case_id}/report` *(Exportable executive HTML/PDF & REVENANT-compatible `findings.json`)*

### 7.4 End-User / DFIR Analyst Screen Design
Designed strictly for security analysts (zero stack traces, hyperparams, CV tables, or internal developer column dumps on the main UI):
1. **Top Case Banner & Disclaimer:** Persistent plain-language banner: **`"Triage Assistance Only — ML Leads Prioritize Investigation; Every Item Is a Lead, Not an Automated Verdict."`** alongside Host ID, Snapshot UTC, Artifact Count (`~4,414`), Active Model Name (model-agnostic badge), and Export Report button.
2. **Tab 1 — Confirmed Rule Findings (`F-xxxx`, Known Threats):** Filtered cards sorted by severity/ML priority showing Rule Name, MITRE ATT&CK badge (strictly from deterministic rule), Path/Command/Hash IOCs, and plain-English *"Why ML also prioritized this"*.
3. **Tab 2 — Prioritized Unruled Leads (`L-xxxx`, Suspicious Anomalies):** Ranked investigation queue displaying Calibrated Risk Band (`High`/`Medium`/`Watch`), `technique_id: Unattributed (Lead Only)`, and **3 Human-Readable Reason Pills** generated from non-null SHAP feature drivers + expandable Evidence Drawer (`path`, `command_line`, `signature`, `sha256`).
4. **Right-Hand Analyst Triage Rail (Layer 4):** One-click disposition, analyst notes, IOC copy, and real-time progress tracker (`12 / 30 Leads Reviewed`).

---

## 8. Risks, Supervisor Approval, Blinded Reviewer Workload & Locked Execution Decisions

### 8.1 Approved Governance Status (`Supervisor Marawan — AASTMT`, `2026-11-25`)
Supervisor Marawan (AASTMT) granted formal approval on `2026-11-25` (building on the `2026-11-23` containment sign-off) for the re-scoped comparative study covering:
1. **Collection Volume Scaling:** Scaling to Tier 2 Target **`1,000` usable samples (`800` dev / `200` blind test; `~2,000+` detonation attempts + `200` benign runs)**, with Tier 1 (`400` usable, `30` families, `15` blind test) serving as Checkpoint 1 after Stage A pilot yield verification.
2. **Explicit Exclusion Mandate:** Enforcing strict fail-closed exclusion of **ransomware, wipers, and self-propagating worms** plus standalone runnable `.exe` PE verification across curator, pilot staging, and container extraction (`OD-V2-08`).

### 8.2 Key Technical & Operational Risks + Mitigations
1. **Realized Detonation Yield Below 50%:** If executed persistence/artifact yield drops to `~35%`, Target requires `~2,860` attempts (`+~38h` compute). *Mitigation:* Stage A pilot measures empirical yield across 7 allowed families first; fallback explicitly pre-defined at Tier 1 (`400`) Checkpoint 1.
2. **Continuous Unattended Thermal / NVMe Wear (`~137h`):** Continuous QEMU boots over 15–18 days on a laptop can cause thermal throttling or sleep interruptions. *Mitigation:* Run in 8–10 hr monitored overnight/day blocks with `systemd-inhibit` against sleep, SSD SMART health checks, overlay deletion immediately post-extract, and `completed_runs.jsonl` resumable batch checkpoints after every run.
3. **MalwareBazaar Non-Destructive Family Scarcity Past ~60 Families:** Excluding ransomware/worms/C2-dead families compresses the abundant Windows PE tail around `~60–75` clean families. *Mitigation:* Lock `50–60` families at Target Tier (`20–25` blind test) rather than chasing hollow `1`-sample families for Stretch (`80`).
4. **`CLEAN_IMAGE_PARITY_REPORT.md` 3 Minor Live-Diffs:** Documented in [`CLEAN_IMAGE_PARITY_REPORT.md`](CLEAN_IMAGE_PARITY_REPORT.md); benign workload generation replaces placeholders with real `1,500–2,000` unique disjoint benign drift files so background OS drift is completely isolated and modeled cleanly.
5. **Dual-Lane Network Isolation Drift Avoided:** `2`-lane `virbr2` is not used; locked **1 Lane Pipelined** keeps all VM containment strictly on verified `virbr1`.

### 8.3 Feasible Blinded Human Reviewer Workload (`OD-V2-10` Fix)
Because `review_v2.py` previously exported 100% of positive rows (an unfeasible `~5,600–6,800` rows), Sprint 1 caps export at a **stratified blinded sample**:
- **Primary Blinded Reviewer (Mokh's Friend):** **`400` rows total** (`200` `attacker_induced` stratified across `100` executed + `100` dormant across all blind families + `100` `benign_drift` + `100` `ambiguous_unattributed`). At `~60–90s/row`, total effort is **`6.5–10 hours`**, giving a tight $\pm 3.0\%$ 95% Wilson CI on label precision/accuracy.
- **20% Overlap Slice (Mokh for Cohen's $\kappa$):** **`80` stratified rows** (`1.5–2.0 hours`), giving $\text{SE}(\kappa) \approx 0.045$ (`80%` overlap agreement check without exhausting reviewers).

### 8.4 Locked Execution Decisions (`2026-11-25`)

1. **Scale Tier Lock:** **Tier 2 Target (`1,000` usable samples: `800` dev / `200` blind test + `200` benign runs, `50–60` families)**, with **Tier 1 (`400` usable, `30` families, `15` blind test)** as Checkpoint 1 after Stage A pilot.
2. **Dormant Staging Strategy:** **Hybrid Strategy** (`executed`-first gating; batch-stage dev dormant `@ 16/overlay` = `2.2h` without re-baking `win11_base.qcow2` + strictly `1`-sample-per-boot for all `200` blind-test dormant runs = `7.9h`).
3. **Collection Concurrency:** **1 Lane Pipelined** (`~137h` active, extract Run `i` concurrently while Run `i+1` boots via `win11_overlay_<run_id>.qcow2`, zero second-bridge `virbr2` risk).
4. **Base-Hash Cadence During Unattended Runs:** **Fast per-run immutability (`+i`/`0444`/inode + full NVRAM SHA-256 inside `finally:`) + full `129 GiB` `win11_base.qcow2` SHA-256 every `25` runs & batch start/end/abort**.
5. **Equal Tuning Budget, Calibration & `TabPFN` Policy:** **Enforce `20` EQUAL trials across ALL tuned models** (Tier A, Tier B CUDA, and Tier C capped instance) inside **`5`-fold outer × `3`-fold inner** family-grouped CV (`K=5` seeds `[42..46]`), fitting calibrators (`Platt`/`Isotonic`) and `1%` FPR thresholds strictly on **natural-prevalence dev OOF or exact dev-only Bayes prior-odds adjustment**. Keep `TabPFN` strictly optional/exploratory (skip if weights/HF block).
6. **Package Additions & Benign Quotas:** Install `lightgbm`, `catboost`, `optuna`, `fastapi`, `uvicorn`, `pydantic`, `pyzipper`, `ppdeep`, and `py-tlsh` into `.venv`; generate real non-quantized benign drift (`1,500–2,000` unique files + `200–400` persistence entries across strictly disjoint `dev` and `blind_test` pools).
7. **Blinded Human Review Pack Cap:** `src/v2/review_v2.py` capped at **`400` stratified primary rows (`200` pos / `100` drift / `100` ambiguous) / `80` overlap rows (20% Cohen's $\kappa$)**.
8. **End-User Screen & API Timing:** Deferred cleanly to Sprint 2 (post-Stage A pilot) under the hard air-gap separation design (§7).
