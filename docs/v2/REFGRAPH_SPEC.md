# DFIR-Triage ML v2 — Static Referential Graph Specification (`v2_refgraph`)

**Status:** `Phase 1 Specification (OD-V2-11, OD-V2-13, OD-V2-16, OD-V2-17, OD-V2-18 confirmed by Mokh 2026-11-23)`  
**Evaluation Placement:** Secondary pre-registered arm **strictly outside** the primary `full_20`/`no_content` dual-configuration winner rule (`OD-V2-13`).  
**Prior-Art Disclaimer:** All external comparative claims remain `UNVERIFIED` pending manual primary-source review in [`NOVELTY_VERIFICATION.md`](NOVELTY_VERIFICATION.md). To our knowledge, pending verification, this architecture specifies a stateless, timestamp-free static pointer-resolution and hub-attenuated score propagation pipeline over single cold Windows NTFS images.

---

## 1. Graph Scope & Core Structural Invariants

1. **One Graph Per Disk (Per Run):** Each collected VM disk snapshot (`run_id`) induces an **independent per-disk graph** $G_d = (V_d, E_d)$. Zero edges cross between distinct runs, distinct hosts, or dev/test partitions.
2. **Stateless & Timestamp-Free:** Every node, edge, and edge attribute depends **solely** on static on-disk pointers defined in [`hardening/POINTER_CAPTURE_SPEC.md`](hardening/POINTER_CAPTURE_SPEC.md). No event logs, process trees, Sysmon telemetry, or timestamps participate in graph construction.
3. **Raw Edge Columns Barred From Primary Models:** `ref_targets`, `ref_type`, and `linked_artifact_keys` (`config.REFGRAPH_EDGE_COLUMNS`) alongside all `V2_PROVENANCE_COLUMNS` are inside `config.FORBIDDEN_MODEL_INPUTS` and rejected unconditionally by `assert_no_forbidden_inputs()`.

---

## 2. Node Types & Context-Scoped Virtual Node Splitting

To prevent signed OS utilities (`rundll32.exe`, `svchost.exe`, `powershell.exe`, `cmd.exe`, `dllhost.exe`, `mshta.exe`) from acting as bidirectional bridges across unrelated tasks, Variant `(c)` splits invocation context from static binary identity:

| Node Type | Represents | Key Attributes / Canonical ID |
| :--- | :--- | :--- |
| **`PE_FILE`** | Static on-disk file or `$MFT` record (authenticode sig, entropy, size, path) | Canonical normalized filesystem path or `(mft_index, mft_sequence)` |
| **`EXEC_CONTEXT`** *(Virtual Node)* | Single invocation configuration / context (`Task` action, `Service`, `Run` value, `IFEO` entry, `WMI` consumer, `LNK`, or hashed `.pf` record) | Unique `artifact_key#context` per caller |
| **`PERSIST_ENTRY`** | Persistence holder (`PERSIST_TASK`, `PERSIST_SERVICE`, `PERSIST_RUN_KEY`, `PERSIST_STARTUP`, `REGISTRY_ASEP`) | `artifact_key` |
| **`COM_CLSID`** | COM registration key (`HKCU` / `HKLM` / `Wow6432Node` `{GUID}`) | `clsid\|{guid}\|hive\|wow64` |
| **`WMI_COMPONENT`** | `WMI_FILTER`, `WMI_CONSUMER`, `WMI_BINDING` | `artifact_key` |
| **`EXEC_RESIDUE`** | `PREFETCH_RECORD`, `SHIMCACHE_ENTRY`, `AMCACHE_ENTRY` | `artifact_key` |
| **`DIRECTORY`** | NTFS parent directory record | Normalized directory path / `$MFT` parent index |
| **`DANGLING_REF`** | Target pointer whose normalized path or `$MFT` reference cannot resolve to a live on-disk artifact | `dangling\|<ref_kind>\|<target_key>` + MFT reference state |

### Unidirectional `EXECUTES_IMAGE` Invariant
- A static `PE_FILE` node connects to each associated `EXEC_CONTEXT` node via a **unidirectional edge** $\text{PE\_FILE} \xrightarrow{\text{EXECUTES\_IMAGE}} \text{EXEC\_CONTEXT}$.
- Static binary trust/suspicion from the `PE_FILE` informs the invocation context, **but anomaly score from an anomalous Scheduled Task's `EXEC_CONTEXT` CANNOT propagate backward into `C:\Windows\System32\rundll32.exe` (`PE_FILE`) and out to unrelated benign tasks**.

---

## 3. Typed Edges & Deterministic Resolution Rules

| Edge Type | Source Node $\to$ Target Node | Deterministic Resolution Rule | Base Rel Weight |
| :--- | :--- | :--- | :---: |
| **`PERSISTS_TARGET`** | `PERSIST_RUN_KEY` / `REGISTRY_ASEP` / `PERSIST_STARTUP` $\to$ `EXEC_CONTEXT` $\to$ target `PE_FILE`/script | Parse primary executable + script/DLL argument targets after path normalization; emit context node linking caller to payload. | `0.90` |
| **`TRIGGERS_EXEC`** | `PERSIST_TASK` $\to$ `EXEC_CONTEXT` | Extract `<Exec><Command>` + `<Arguments>` (or parsed `TaskCache` `Actions` blob); emit task invocation context. | `0.90` |
| **`INVOKES_COM`** | `PERSIST_TASK` (`<ComHandler><ClassId>`) $\to$ `COM_CLSID` | Match lowercased braced `{GUID}` against disk `CLSID` map (`HKCU > HKLM`, matching bitness / `Wow6432Node` precedence). | `0.95` |
| **`RESOLVES_COM_DLL`** | `COM_CLSID` $\to$ `PE_FILE` | Resolve `InprocServer32` / `LocalServer32` normalized default value (`expanded` path). | `0.95` |
| **`RUNS_SERVICE`** | `PERSIST_SERVICE` $\to$ `EXEC_CONTEXT` | Resolve expanded `ImagePath` binary to `PE_FILE` / context. | `0.85` |
| **`HOSTS_SERVICEDLL`** | `PERSIST_SERVICE` $\to$ `PE_FILE` | When `Parameters\ServiceDll` exists (e.g., `svchost.exe -k <Group>`), connect directly from service invocation context to the expanded `ServiceDll` path. | `0.95` |
| **`WMI_BINDS_FILTER`** / **`WMI_BINDS_CONSUMER`** | `WMI_BINDING` $\to$ `WMI_FILTER`, `WMI_CONSUMER` | Match normalized `__EventFilter` & consumer names (`CommandLineEventConsumer` / `ActiveScriptEventConsumer`). | `0.90` |
| **`WMI_CONSUMER_EXEC`** | `WMI_CONSUMER` $\to$ `EXEC_CONTEXT` $\to$ `PE_FILE`/script | Parse `ExecutablePath` / `CommandLineTemplate` / `ScriptFileName`. | `0.90` |
| **`EXECUTES_IMAGE`** | `PE_FILE` $\to$ `EXEC_CONTEXT` | One-way image identity edge (trust prior only, zero backward smear). | `0.50` *(forward only)* |
| **`LOADED_RESOURCE`** | `EXEC_CONTEXT` (`.pf`) $\to$ `PE_FILE` / `DANGLING_REF` | Resolve Prefetch `pf_file_metrics` `(mft_index, mft_sequence)` against `$MFT`, falling back to normalized `file_path`; weight attenuated by training-pool IHF! | `0.75 * IHF` |
| **`PREFETCH_MATCHES_IMAGE`** *(EXPERIMENTAL)* | `EXEC_CONTEXT` $\to$ `PREFETCH_RECORD` | Direct match on `(exe_name, scca_hash)` for standard apps; forward command-line SCCA hashing for hosting apps (see §6 — **marked EXPERIMENTAL**). | `0.85` |
| **`REFERENCES_FILE`** | `LNK_SHORTCUT` $\to$ `PE_FILE` / `DANGLING_REF` | Resolve `BEEF0004` `(target_mft_index, target_mft_sequence)`, `ObjectId`, or normalized `lnk_target_path_expanded`. | `0.80` |
| **`INVENTORIED_BINARY`** | `AMCACHE_ENTRY` $\to$ `PE_FILE` | Resolve `FileId` (`"0000"+SHA-1`) or normalized `LowerCaseLongPath`. | `0.70` |
| **`CONTAINS_CHILD`** | `DIRECTORY` $\to$ `PE_FILE` | Parent MFT index + sequence match (`$FILE_NAME` parent ref). Heavily damped to prevent directory hub explosion (`System32`). | `0.05 * IHF` |
| **`PARITY_MISMATCH`** | `PERSIST_TASK` / `TaskCache` self-edge or `EXEC_RESIDUE` | Emitted when `TaskCache` entry lacks XML (`task_xml_exists == False`) or stripped `SD`, or when `.pf`/`$MFT` flags deleted reference. | `1.00` *(structural attribute)* |

---

## 4. Path Obfuscation Normalization Rules

Every raw filesystem reference passes through deterministic canonical normalization prior to key matching:
1. Trim whitespace, surrounding single/double quotes, and trailing Windows filename spaces/dots (`"foo.dll "` $\to$ `foo.dll`), replace `/` with `\`, and case-fold ASCII lowercase.
2. Strip NT device/object prefixes (`\??\`, `\\?\`, `\SystemRoot\`, `SystemRoot\`, `\Device\HarddiskVolume#\` mapped dynamically or via candidate volume prefix strip).
3. Expand canonical Windows environment variables (`%SystemRoot%`, `%WinDir%`, `%SystemDrive%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramW6432%`, `%ProgramData%`, `%Public%`, `%ComSpec%`, `%UserProfile%`, `%AppData%`, `%LocalAppData%`, `%Temp%`, `%Tmp%`). Resolve relative bare executables (`explorer.exe`, `rundll32.exe`, `cmd.exe`, `powershell.exe`) against `System32` / PowerShell default search locations if unambiguous.
4. **NTFS Alternate Data Streams (ADS):** Split `base_path:stream_name` (when `:` follows the drive colon at index 1) into `(canonical_base_path, ads_stream)`. Exclude harmless `Zone.Identifier` streams from suspicious execution edges, while linking executable/script ADS paths (`notepad.exe:evil.exe`) to both the host `PE_FILE` and a dedicated ADS node attribute.
5. **DOS 8.3 Short Names:** Build a per-disk `$MFT` lookup map from any `$FILE_NAME` attribute in `DOS` / `WIN32_DOS` namespace (`PROGRA~1`, `MICROS~1`) to its sibling `WIN32` long name matching the exact `(mft_record_number, parent_mft_index, parent_mft_sequence)`.

---

## 5. Four `$MFT` Reference Resolution States

Given any static pointer tuple `(ptr_idx, ptr_seq)` (from Prefetch File Metrics, LNK `BEEF0004`, or `$FILE_NAME` parent ref) looked up in the same disk's `$MFT` table:

| State | Exact Predicate | Structural Interpretation |
| :--- | :--- | :--- |
| **`live_matched`** | Record `ptr_idx` exists in `$MFT`, `mft_in_use == True`, and `mft_sequence_number == ptr_seq` | Active live file/DLL currently present on the NTFS volume. |
| **`deleted_unreused`** | Record `ptr_idx` exists in `$MFT`, `mft_in_use == False`, and `mft_sequence_number == ptr_seq + 1` (or equal under version-specific pre-increment convention) | Unlinked/self-deleted file whose `$MFT` slot has not yet been overwritten (common after self-deleting payloads). |
| **`deleted_reused_or_seq_mismatch`** | Record `ptr_idx` exists in `$MFT`, but sequence diverges beyond single deletion (`mft_sequence_number != ptr_seq` with `mft_in_use == True`, or `abs(mft_sequence_number - ptr_seq) > 1`) | Original file was deleted and its MFT slot was subsequently reallocated; **do NOT join by `mft_index` alone** — emit a dangling/mismatch edge instead to prevent false edges. |
| **`dangling`** | No `$MFT` entry exists for `ptr_idx` (or only a path string exists with no on-disk file record) | Unresolvable pointer / purged record; attach `dangling` indicator edge rather than dropping silently. |

---

## 6. Hosting-App Forward Prefetch SCCA Hashing (**EXPERIMENTAL**)

> [!WARNING]
> **EXPERIMENTAL — TO BE VERIFIED EMPIRICALLY.**  
> Public SCCA reverse-engineering notes (including `libscca` docs; status `UNVERIFIED`) note that Windows hosts (`svchost.exe`, `rundll32.exe`, `dllhost.exe`, `mmc.exe`, and `/prefetch:[0-8]` invocations) fold the command line into their 32-bit Prefetch hash, with Windows 10/11 v30 edge cases potentially incomplete.

- When enabled experimentally, a persistence or LNK `EXEC_CONTEXT` whose executable basename is in `{"svchost.exe", "rundll32.exe", "dllhost.exe", "mmc.exe"}` generates candidate `\Device\HarddiskVolume#\...` + command-line SCCA hashes (OS-version specific) to attempt `PREFETCH_MATCHES_IMAGE` linkage against `<EXE>-<HASH>.pf` records on the same disk.
- During offline validation against clean and controlled Windows 10/11 pilot boots, forward-hash hit accuracy and mismatch rates MUST be measured empirically before relying on hosting-app hashes; unverified hosting-app hashes default to **no speculative Prefetch-to-Context join** (only direct `.pf` internal `pf_file_metrics` $\to$ `PE_FILE` edges and exact command-line string matching are active unconditionally).

---

## 7. Inverse Host Frequency (IHF) & Edge Weighting

For any target entity canonical key $u$ (e.g., `c:\windows\system32\ntdll.dll` vs `c:\programdata\side.dll`), compute disk document frequency **strictly across training-pool disks** ($d \in \mathcal{D}_{\text{train}}$ — NEVER including validation or blind-test disks):

$$\text{df}_{\text{train}}(u) = \sum_{d \in \mathcal{D}_{\text{train}}} \mathbb{I}\left[\exists e \in E_d \text{ targeting } u\right]$$

$$\text{IHF}_{\text{train}}(u) = \frac{\log\left(\frac{1 + |\mathcal{D}_{\text{train}}|}{1 + \text{df}_{\text{train}}(u)}\right)}{\log(1 + |\mathcal{D}_{\text{train}}|)} \in (0, 1]$$

- Universal OS libraries appearing in every training Prefetch set (`ntdll.dll`, `kernel32.dll`, `kernelbase.dll`) satisfy $\text{df}_{\text{train}}(u) \approx |\mathcal{D}_{\text{train}}|$ so $\text{IHF}_{\text{train}}(u) \to 0$.
- Previously unseen / rare user-space targets ($\text{df}_{\text{train}}(u) = 0$) receive maximum coupling $\text{IHF}_{\text{train}}(u) = 1.0$.
- Effective directed coupling weight along edge $e = (v \to u, r)$ with relation base weight $w_r$:
  - Control-indirection & structural parity edges: $w_e = w_r$.
  - Resource/containment edges (`LOADED_RESOURCE`, `CONTAINS_CHILD`): $w_e = w_r \cdot \text{IHF}_{\text{train}}(u)$.

---

## 8. Three Interpretable Propagation Variants (`OD-V2-17`)

Let $s^{(0)} \in \mathbb{R}^{|V_d|}$ be the out-of-fold (OOF) base ranker probability/anomaly vector per node on disk $d$ (missing/virtual context nodes initialized with $s^{(0)}_v = 0$):

1. **Variant `(a)` — Base Ranker Alone:**
   $$\hat{s}^{(a)} = s^{(0)}$$
   Zero graph propagation; isolates base tabular ranker quality.

2. **Variant `(b)` — Naive Undirected Propagation (Hub-Collapse Baseline):**
   Constructs the symmetric adjacency matrix $A_{\text{sym}}$ over unsplit merged entity nodes (ignoring context splitting, directionality, and IHF attenuation), row/symmetrically normalized $P_{\text{naive}} = D_{\text{sym}}^{-1/2} A_{\text{sym}} D_{\text{sym}}^{-1/2}$, iterating:
   $$s^{(t+1)} = (1 - \alpha) s^{(0)} + \alpha P_{\text{naive}} s^{(t)}, \quad \alpha \in (0, 1)$$
   Directly tests and exposes universal OS hub collapse (score smearing across shared hubs such as `ntdll.dll` and `rundll32.exe`).

3. **Variant `(c)` — Hub-Attenuated Typed Propagation (Context-Split Directed Diffusion):**
   Constructs the context-split directed graph (§2–§3) using typed relation multipliers $w_r$ and **frozen training-pool IHF weights**. Let $W \in \mathbb{R}_{\ge 0}^{|V_d| \times |V_d|}$ hold non-zero directed propagation couplings (symmetric or scaled bidirectional coupling strictly **excluding** reverse traversal across `EXECUTES_IMAGE`, where $\text{EXECUTES\_IMAGE}$ propagates **only** $\text{PE\_FILE} \to \text{EXEC\_CONTEXT}$):
   $$P_{\text{att}, ij} = \frac{W_{ji}}{\max\left(1.0, \sum_k W_{jk}\right)}, \quad s^{(t+1)} = (1 - \alpha) s^{(0)} + \alpha \, P_{\text{att}}^{\top} s^{(t)} + \beta_{\text{path}} \, \text{context\_boost}(s^{(0)}, W)$$
   Every node's final propagated score $\hat{s}^{(c)}_i$ decomposes additively into its own prior $(1-\alpha) s^{(0)}_i$ plus explicit source-node & edge-type contributions $(\Delta_{j \to i}, r, w_e)$ for forensic auditability.
   *(Heterogeneous GNNs such as R-GCN/GAT are deferred outside v2 core per `OD-V2-18`.)*

---

## 9. Nested CV Hyperparameter Tuning & Strict Anti-Leakage Rules

### Hyperparameter Tuning (`OD-V2-06`)
- Propagation hyperparameters — damping $\alpha \in [0.1, 0.85]$, relation-weight scale factors (control vs resource vs containment vs `EXECUTES_IMAGE` trust prior), and diffusion steps $T$ (or convergence tolerance) — are tuned **exclusively inside inner nested family-grouped dev CV** using the **exact same trial budget (`N_trials = 30`, fallback `20`)** as `rf`, `xgb`, `iforest`, `mlp`, `ae`, and `lr`.

### Non-Negotiable Anti-Leakage Rules
1. **OOF Base Scores Only:** Input scores $s^{(0)}$ passed to propagation inside dev CV or `--final` graph tuning MUST be strictly **out-of-fold** predictions (`run_nested_family_cv`), never in-sample training predictions (which overfit positives and would leak label certainty across edges).
2. **Training-Pool-Only Frequency & Degree Statistics:** `RefGraphIDFModel` ($\text{df}_{\text{train}}$, $|\mathcal{D}_{\text{train}}|$, degree statistics) fits **solely on training fold disks**. Calling `.transform` / propagation on validation or blind-test disks **never** updates counts or inspects validation/test degree distributions.
3. **Zero Provenance / Process / Timestamp Leakage:** Passing any column matching `LABEL_COL`, `label_reason`, `V2_PROVENANCE_COLUMNS`, `ORACLE_FEATURES`, `RULE_FEATURES`, process-tree columns (`pid`, `ppid`, `parent_name`, `process_tree_root_guid`), Sysmon fields, or timestamps into the graph builder MUST raise `LeakageError`.
