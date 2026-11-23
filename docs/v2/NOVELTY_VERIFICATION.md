# DFIR-Triage ML v2 — Prior-Art & Literature Novelty Verification Ledger

**Status:** `ALL EXTERNAL CITATIONS AND CLAIMS REMAIN UNVERIFIED`  
**Source Audited:** [`docs/v2/research/concept_a_gap_audit.md`](research/concept_a_gap_audit.md) (archived external research report covering citations `[1]`–`[137]`, tagged **`UNVERIFIED external report`**)  
**Policy:** Treat every venue, bibliographic reference, URL, metric, and technical claim below as **`UNVERIFIED`** until inspected directly in its primary source (PDF/DOI/repository). Never cite unverified numbers or priority claims in pre-registration docs or downstream writing. To our knowledge, pending verification, the proposed static dead-disk referential graph design (`v2_refgraph`) combines pointer-resolved static cold-disk links with hub-attenuated propagation under frozen training-pool statistics.

> [!CAUTION]
> **Reviewer Verification Flags (Anomalous/Future 2026 IDs, Venues & Unverified Numerical Claims)**
> 1. **Anomalous / Future-Dated 2026 Identifiers & Venues to Verify Against Primary Archives:**
>    - `arXiv:2610.35151` (`[64]`, `[65]`: log-tampering provenance audit)
>    - `arXiv:2611.01225` / `ResearchGate 417377652` (`[27]`, `[28]`, `[124]`: Chudasama et al., graph memory forensics & label–signal mismatch)
>    - `DFRWS USA 2026` (`[53]`, `[137]`: GATOR presentation)
>    - `ASIA CCS 2026` (`[63]`: van Nielen et al. Windows persistence systematization)
>    - `EuroS&P 2026` / `HAL hal-05653376v1` (`[12]`: GRAAL)
>    - `Applied Ontology 2026` / `DFDS 2025` / `ECU 9373` (`[3]`, `[51]`, `[52]`: FEAR & Autopsy Ontology)
>    - `MDPI Nov 2026` (`[60]`: `2673-6756/6/4/102`, HVEA-SIFTING)
>    - `IJSCI Volume 3 Issue 11 November 2026` (`[120]`) and `ResearchGate 417247107` (`[55]`)
>    - `HCIS 2026` / `hcisj.com` (`[62]`: Hong et al. 2026 NTFS USN)
> 2. **Exact Numeric Claims Barred From Citation Until Verified in Primary PDFs:**
>    - `0.96 ROC-AUC`, `6,271 hosts`, `top 2.6% vs 12.3%` (`[5]`, Autoencoder + Log-Entropy vs DS4N6)
>    - `95.19% F1` (`[15]`, `[16]`, DAPTASK)
>    - `93.9% AP`, `98.8% recall`, `16 IoT scenarios`, `3.68% overhead`, `ALchemist 78.4% P / 95.3% R` (`[6]`, ARTISAN)
>    - `55.2%` malware persistence prevalence; `72` techniques; `24.9%` FNR (Autoruns), `34.9%` FNR & `38/72` coverage (PersistenceSniper), `42.1%` FNR & `72.5%` FPR (Capa) (`[63]`)
>    - `28/38` log-trusting provenance detectors (`[64]`, `[65]`)
>    - `29.8%` actors / `33.7%` campaigns self-delete; `1.8%` Prefetch executions with DLLs absent vs memory (`[4]`, `[80]`)
>    - `53%` heuristic trigger rate on nominal benign rows (`[27]`, `[28]`, `[124]`)
>    - `31 MiB` leading prefix SHA-1 limit on Amcache `FileId` (`[36]`) and `1,024` Prefetch entry rollover (`[70]`)
>    - `1 MB` WMI-Activity / `15 MB` PowerShell / `64 MB` Sysmon default EVTX caps (`[66]`)
>    - `0.86 ROC-AUC / 0.77 F1` (`[62]`, Hong et al. 2026)
>    - `79% malware / 99% benign / 0.0001 FPR` across `119M` machines / `10.1B` files (`[19]`, `[20]`, AESOP) and `37B edges / 48M machines / 903M files` (`[17]`, Polonium)
>    - `> 5x` faster Label Propagation vs Loopy Belief Propagation (`[26]`, `arXiv:2411.06239`)
>    - `8 of 9` benchmarks won by VELOX (`[7]`, Bilot et al.)

---

## Group A — Commercial & Open-Source Dead-Disk / Forensic Triage Tools

| ID | Prior Work / System | Reported Venue / Source (Audit Report) | Claim Attributed in `concept_a_gap_audit.md` | What Must Be Checked in Primary Source | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A-01** | **Magnet AXIOM Connections** `[1, 45]` | Commercial DFIR suite (`https://www.magnetforensics.com/blog/axiom-connections-qa-part-1/`, `part-2`) | Constructs non-temporal artifact link graphs from parsed/carved NTFS using rule-based links (path, hash, URL, VolSerial, LNK-to-USB Registry) without anomaly propagation | Exact supported link types, cold-disk schema scope, and absence of risk propagation | `UNVERIFIED` |
| **A-02** | **Cyber Triage** `[35, 46–49]` | Commercial DFIR triage (`https://docs.cybertriage.com/...`, `cybertriage.com`) | Combines disk + EDR/EVTX pipelines; scores isolated artifacts via AV/YARA/Hayabusa heuristics; pivots via Recommendation Engine after hits | Separation of dead-disk vs live-EDR inputs and whether cross-artifact scoring propagates on-host | `UNVERIFIED` |
| **A-03** | **Belkasoft X Connection Graph** `[58, 59]` | Commercial DFIR suite (`https://belkasoft.com/connection-graphs-complex-cases`, `connection_graph_full`) | Visualizes human communication networks (calls, SMS, chats, emails) rather than Windows OS persistence/execution pointers | Exact entity/edge types supported by Belkasoft X | `UNVERIFIED` |
| **A-04** | **Plaso (`log2timeline`)** `[32]` | Open-source DFIR (`https://kitploit.com/en/tools/github/log2timeline/plaso`) | Flattens heterogeneous artifacts into chronological super-timelines without referential graph scoring | Official Plaso docs on non-temporal output formats and structural linkage | `UNVERIFIED` |
| **A-05** | **Hayabusa** `[34]` | Open-source DFIR (`https://www.cyberengage.org/post/hayabusa-a-powerful-log-analysis-tool-for-forensics-and-threat-hunting`) | Evaluates Sigma rules over `.evtx` event logs into CSV/JSON timelines, delegating graphs to external Neo4j imports | Official Hayabusa repo/docs confirming EVTX-only scope | `UNVERIFIED` |
| **A-06** | **KAPE & Eric Zimmerman EZ Tools (`MFTECmd`, `PECmd`, `RECmd`, `AmcacheParser`, `LECmd`)** `[35, 36, 102]` | Open-source DFIR (`https://docs.cybertriage.com/...`, `https://www.amcacheparser.com/...`, `https://binaryforay.blogspot.com/...`) | Outputs flat unscored per-artifact CSVs (`$MFT`, Prefetch, Registry, Amcache, LNK) for manual analyst pivoting | Tool output schemas, Amcache `FileId` parsing behavior, and `BEEF0004` extraction | `UNVERIFIED` |
| **A-07** | **Fox-IT `dissect` & `dissect.thumbcache`** `[37–40, 83, 85]` | Open-source DFIR (`https://github.com/fox-it/dissect`, `https://docs.dissect.tools/`, Hunt & Hackett blog) | Exposes target plugins (`mft`, `prefetch`, `registry`, `tasks`, `amcache`, `usnjrnl`, `sru`, `shellitem`); workflows serialize records into JSONL for Timesketch/Elastic | Exact plugin pointer fields exposed in `dissect.target` and published graph extensions | `UNVERIFIED` |
| **A-08** | **Timesketch + Neo4j Discussions** `[41]` | Open-source DFIR (`https://github.com/google/timesketch/discussions/1739`) | Graph plugins target narrow log-derived slices (logins, service launches, downloads) rather than cold NTFS static pointer propagation | Timesketch analyzer source/docs and Neo4j integration status | `UNVERIFIED` |
| **A-09** | **Autopsy & Central Repository** `[43, 44]` | Open-source DFIR (`https://www.sleuthkit.org/autopsy/history.php`, Medium blog `[43]`) | Performs exact-match cross-case hash/email/device correlation rather than intra-host static graph risk propagation | Official Sleuth Kit / Autopsy documentation | `UNVERIFIED` |
| **A-10** | **`libscca` Prefetch Spec** `[78]` | Open-source spec (`https://github.com/libyal/libscca/.../Windows%20Prefetch%20File%20(PF)%20format.asciidoc`) | Documents v23/v26/v30 File Metrics 8-byte MFT references and notes Windows 10 v30 command-line SCCA hashing caveats | Exact byte offsets and v30 command-line hashing completeness in `libyal/libscca` | `UNVERIFIED` |
| **A-11** | **GhostTask** `[88]` | Offensive/security repo (`https://kitploit.com/de/tools/github/netero1010/ghosttask`) | Modifies Scheduled Task `TaskCache` Registry keys directly without XML files or clears Security Descriptors | Primary GitHub repository (`netero1010/ghosttask`) for exact mechanisms | `UNVERIFIED` |
| **A-12** | **PowerForensics** `[103]` | Open-source DFIR (`https://powerforensics.readthedocs.io/`) | Raw NTFS/Registry parsing in PowerShell without cross-artifact graph risk propagation | Official PowerForensics documentation | `UNVERIFIED` |

---

## Group B — DFIR Ontologies, Knowledge Graphs & Acquisition Dependency Graphs

| ID | Prior Work / System | Reported Venue / Source (Audit Report) | Claim Attributed in `concept_a_gap_audit.md` | What Must Be Checked in Primary Source | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **B-01** | **IoI Framework** `[2, 50]` | Open-source DFIR (`https://github.com/ioi-framework/ioi-framework`, `https://ioi-framework.github.io/executerules/`) | Builds named CASE/UCO RDF graphs (`$MFT`, USN, `.lnk`, Prefetch, `.evtx`) with SPARQL boolean contradiction rules (`FILTER NOT EXISTS`), without continuous score propagation | Exact SPARQL rule set, supported cold-disk inputs, and absence of anomaly scoring | `UNVERIFIED` |
| **B-02** | **FEAR & Autopsy Ontology** `[3, 51, 52]` | DFDS 2025 / *Applied Ontology* 2026 (`https://ro.ecu.edu.au/ecuworks2022-2026/9373`, `viewcontent.cgi?article=10373`, Researcher.life `[52]`) | Declarative GFEAR scripts map Autopsy Blackboard artifacts into OWL/RDF + SWRL deduction rules; report claims anomaly detection is explicitly absent | Actual publication dates, peer-reviewed DOIs, SWRL rules, and scope statement | `UNVERIFIED` |
| **B-03** | **GATOR** `[53, 137]` | DFRWS USA 2026 presentation (`https://dfrws.org/presentation/gator-.../`, `dfrws.org/usa-2026-program/`) | Combines `$MFT`, Prefetch, Amcache, SRUM, EVTX using IF + AE + HMM + heuristics, then HDBSCAN temporal episode clustering | Presentation slides/abstract, dependency on EVTX/timestamps, and graph construction order | `UNVERIFIED` |
| **B-04** | **FACE / SADFC / ForensicFlow / Schelkoph et al. / Unified Knowledge Graph** `[31, 54, 56, 57]` | Academic DFIR 2015–2024 (`ResearchGate 352376376`, `378928049`, `280648329`, Semantic Scholar `9c5ee68...`) | Focus on temporal event reconstruction, ontology interoperability, or RAM+disk fusion; report notes minimal/absent continuous malware score propagation | Exact bibliographic metadata, disk-vs-RAM assumptions, and scoring mechanisms in each paper | `UNVERIFIED` |
| **B-05** | **Multi-Agent Traceable Semantic Graph** `[55]` | Preprint/paper (`https://www.researchgate.net/publication/417247107_...`) | Cited in audit report regarding traceable evidence vs computed propagation paths | Actual authorship, publication status, and traceability model in `[55]` | `UNVERIFIED` |
| **B-06** | **DF-LogGraph** `[68]` | Academic DFIR (`https://koreascience.kr/article/JAKO202503743251209.pub`) | GraphRAG-based forensic log framework listed in related ontology/graph lineage | Venue, input log scope, and cold-disk applicability | `UNVERIFIED` |
| **B-07** | **HVEA-SIFTING** `[60]` | MDPI Nov 2026 (`https://www.mdpi.com/2673-6756/6/4/102`) | Models Windows artifacts in a 4-tier, 10-layer dependency graph for selective evidence preservation during acquisition (XP/Vista/11), not post-hoc anomaly inference | Actual MDPI publication date, DOI verification, and preservation-vs-detection distinction | `UNVERIFIED` |

---

## Group C — Persistence Scanners, Tabular/Single-Artifact DFIR ML & Memory-Forensics Graphs

| ID | Prior Work / System | Reported Venue / Source (Audit Report) | Claim Attributed in `concept_a_gap_audit.md` | What Must Be Checked in Primary Source | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **C-01** | **Autoencoder + Log-Entropy Prioritizer & DS4N6** `[5]` | Academic DFIR / ResearchGate (`publication/385929059_AI-Driven_Prioritization...`) | Row-level AE + logarithmic entropy across 8 Windows sources including Event Logs; claims `0.96 ROC-AUC` across `6,271` hosts and top `2.6%` vs `12.3%` (DS4N6), evaluating each row independently | PDF verification of host count, AUC, log dependency, and DS4N6 comparison | `UNVERIFIED` |
| **C-02** | **Windows Malware Persistence SoK (van Nielen et al.)** `[63]` | ASIA CCS 2026 (`https://conand.me/publications/vannielen-persistence-2026.pdf`) | Systematizes `72` persistence techniques across Registry/Filesystem/WMI; claims `55.2%` sample persistence rate and FNRs (`24.9%` Autoruns, `34.9%` PersistenceSniper on `38/72`, `42.1%` FNR / `72.5%` FPR Capa) | Publication status, exact tool versions, evaluation dataset, and error rates in PDF | `UNVERIFIED` |
| **C-03** | **Duby et al. (2022)** `[4, 80]` | Academic PDF / NSF PAR (`duby_detecting_2022.pdf`, `par.nsf.gov/servlets/purl/10333089`) | Evaluates Prefetch ML (`Jaccard kNN`); claims `29.8%` actors / `33.7%` campaigns self-delete, `1.8%` DLL omission rate in Prefetch, and ubiquitous `ntdll.dll`/`kernel32.dll`/`kernelbase.dll` | Primary PDF numbers for self-deletion stats, Prefetch DLL completeness, and evaluation split methodology | `UNVERIFIED` |
| **C-04** | **Alsulami & Mancoridis (2018)** `[4, 61]` | arXiv (`https://arxiv.org/pdf/1811.07842`) | Single-artifact Prefetch ML classification without cross-artifact referential propagation | Dataset, feature set, and cold-disk assumptions in `[61]` | `UNVERIFIED` |
| **C-05** | **Hong et al. (2026)** `[62]` | Journal (`http://hcisj.com/articles/issue_view.php?wr_id=682&page`) | Tabular ML on NTFS USN Journal time slots reporting `0.86 ROC-AUC` and `0.77 F1`, without cross-artifact graph propagation | Exact bibliographic citation, feature list, and evaluation protocol | `UNVERIFIED` |
| **C-06** | **DAPTASK (2025)** `[15, 16]` | Academic paper (`cybersecurityjournal.info/.../3962...pdf`, `ResearchGate 399695381`) | Reports `95.19% F1` on malicious Scheduled Tasks using Sysmon telemetry rather than cold-disk snapshots | Confirm Sysmon dependency, dataset composition, and F1 methodology | `UNVERIFIED` |
| **C-07** | **Nisslmueller (LOLBin Unsupervised ML Thesis)** `[72]` | Master's thesis (`essay.utwente.nl/.../nisslmueller_MA_EEMCS.pdf`) | Cited regarding LOLBin execution supernodes and unsupervised detection | Telemetry source (process logs vs disk) and evaluated LOLBin classes | `UNVERIFIED` |
| **C-08** | **Chudasama et al. — Label–Signal Mismatch** `[27–29, 124]` | `arXiv:2611.01225` / ResearchGate `417377652` | Applies temperature-scaled GINE + one-class encoders to **volatile RAM** dumps; flags `53%` heuristic trigger rate on unverified benign rows and matched-pair LOFO pitfalls | Check actual arXiv ID validity (`2611.01225`), publication date, volatile RAM vs dead-disk scope, and `53%` figure | `UNVERIFIED` |
| **C-09** | **Elastic Prebuilt Persistence Rules** `[115, 135]` | Vendor docs (`elastic.co/docs/reference/security/prebuilt-rules/...`) | Event-driven runtime rules for Scheduled Tasks and Services Registry changes | Verify rule conditions depend on live endpoint telemetry | `UNVERIFIED` |

---

## Group D — Spatial-Snapshot, File-Relation, Network & Runtime Provenance / Propagation Systems

| ID | Prior Work / System | Reported Venue / Source (Audit Report) | Claim Attributed in `concept_a_gap_audit.md` | What Must Be Checked in Primary Source | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **D-01** | **ARTISAN** `[6]` | USENIX Security 2024 (`usenixsecurity24-yu-le.pdf`) | Logless IoT forensic graph via ZFS spatial copy-on-write deltas + nounlink preservation; infers WCPG via Datalog + TF-IDF weight propagation (`93.9% AP / 98.8% R` across `16` scenarios, `3.68%` overhead vs ALchemist `78.4%/95.3%`) | Primary USENIX PDF checking ZFS instrumentation requirements, TF-IDF formula, and reported numbers | `UNVERIFIED` |
| **D-02** | **Polonium** `[17, 23]` | SDM / covert.io (`Polonium...pdf`, `doi/10.1137/1.9781611972818.12`) | Fleet-scale Belief Propagation on bipartite file-machine graph (`> 37B` edges, `48M` machines, `903M` files) | Exact scale stats and proof it requires cross-host fleet prevalence unavailable on a single cold disk | `UNVERIFIED` |
| **D-03** | **AESOP** `[19, 20]` | KDD 2014 (`14_kdd_aesop.pdf`, ResearchGate `263655298`) | Locality-Sensitive Hashing over `119M` machines / `10.1B` files propagating co-occurrence reputation (`79%` malware, `99%` benign at `0.0001 FPR`) | Primary KDD PDF for numbers and fleet dependency | `UNVERIFIED` |
| **D-04** | **Ni et al. (WISE 2015)** `[21, 22]` | WISE 2015 (`zybuluo.com` note, Google Scholar `mo0BzQoAAAAJ`) | Label propagation over k-NN file-relation graphs | Original Springer/WISE paper (avoid secondary Chinese note) to check feature inputs | `UNVERIFIED` |
| **D-05** | **Liu et al. (ASONAM 2014)** `[25]` | ASONAM 2014 (`2014-liu-ASONAM-dmc.pdf`) | HTTP client-server score propagation showing unweighted hub inflation from popular servers like `google.com` | Primary PDF confirming hub-inflation mechanism | `UNVERIFIED` |
| **D-06** | **Microsoft DNS Graph Propagation** `[24]` | ICASSP 2021 (`MaliciousDNS_ICASSP2021.pdf`) | Host-domain graph score propagation for DNS/web detection | Primary PDF confirming enterprise DNS log dependency | `UNVERIFIED` |
| **D-07** | **Web-Scale Threat Intel Graph Mining** `[26]` | `arXiv:2411.06239v1` (`arxiv.org/html/2411.06239v1`) | Reports Label Propagation runs `> 5x` faster than Loopy BP with steadier convergence while matching Label Spreading | Actual arXiv HTML/PDF experimental setup and threat-intel graph data | `UNVERIFIED` |
| **D-08** | **Bilot et al. — PIDS Systematization** `[7]` | USENIX Security 2025 (`usenixsecurity25-bilot.pdf`) | Evaluates 8 PIDS (`SIGL`, `THREATRACE`, `NODLINK`, `MAGIC`, `KAIROS`, `FLASH`, `R-CAID`, `ORTHRUS`) + `VELOX`; catalogs pitfalls (`SC2` 2-hop inflation, `SC4` test tuning, `SC5` cross-run swings `1.00 -> <0.1`, `SC6` test-fitted embeddings); claims VELOX beat GNNs on `8/9` benchmarks | Primary USENIX PDF verifying benchmark outcomes, pitfall codes (`SC2/4/5/6`), and DARPA runtime scope | `UNVERIFIED` |
| **D-09** | **CamFlow** `[8]` | ACM CCS 2018 (`ccs-2018.pdf`) | Whole-system runtime kernel provenance capture framework | Confirm continuous LSM kernel instrumentation requirement | `UNVERIFIED` |
| **D-10** | **MORSE** `[9]` | IEEE S&P 2020 (`morse20.pdf`) | Subject-tag attenuation & exponential decay combating runtime dependency explosion | Exact tag decay equations in `morse20.pdf` | `UNVERIFIED` |
| **D-11** | **NoDoze** `[10]` | NDSS 2019 (`ResearchGate 348915407`) | Runtime behavioral execution partitioning + regularity-score network diffusion & path anomaly scoring | Exact execution partitioning vs path anomaly formulas | `UNVERIFIED` |
| **D-12** | **DepImpact, Dossier, TAPAS, GRAAL, ProGraPher** `[11–14, 111]` | USENIX Sec '22/'23/'25, NDSS '22, EuroS&P '26 (`sec22summer_fang.pdf`, `usenixsecurity25-zhang-bo-tapas.pdf`, `hal-05653376v1`, `dartlab.org`, `usenixsecurity23-yang-fan.pdf`) | Runtime dependency-graph triage/propagation requiring continuous audit telemetry (`ETW`/`Auditd`/`CamFlow`) | Primary PDFs for telemetry assumptions (especially GRAAL 2026) and scoring methods | `UNVERIFIED` |
| **D-13** | **Log-Tampering Provenance Audit** `[64, 65]` | `arXiv:2610.35151` (`arxiv.org/pdf/2610.35151`) | Audits `38` provenance detectors; claims `28/38` assume untampered logs and lack deleted/forged record bounds | Verify actual arXiv ID (`2610.35151`), date, paper list, and `28/38` count | `UNVERIFIED` |
| **D-14** | **Provenance Belief Propagation & Audit-Log Analysis** `[18, 118, 119]` | IJCAI 2019 (`proceedings/2019/580`), KCL portal `[119]`, GitHub `jun-zeng/Audit-log-analysis` `[118]` | Damped Belief Propagation / inductive semi-supervised BP on provenance/factor graphs | Specific formulation and audit-log assumptions in each cited source | `UNVERIFIED` |
| **D-15** | **GNN Over-Smoothing, JK-GNN & MatchGNet** `[116, 117, 121–123]` | `arXiv:2201.07537`, MDPI `2673-6470/6/4/94`, ResearchGate `363870071`/`334844161`, TowardsDataScience `[117]` | Jumping-Knowledge aggregation & invariant graph modeling cited to motivate deferred GNN comparisons | Primary papers confirming Android/runtime scope vs cold NTFS applicability (`OD-V2-18` defers GNNs) | `UNVERIFIED` |

---

## Group E — Anti-Forensics, Windows Artifact Quirks & Evaluation Corpora

| ID | Prior Work / System | Reported Venue / Source (Audit Report) | Claim Attributed in `concept_a_gap_audit.md` | What Must Be Checked in Primary Source | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **E-01** | **Breitinger et al. — NTFS Timestomping** `[67, 69]` | *FSI: Digital Investigation* / DFRWS 2020 (`dfrws.org/.../2020_Forensic-Science-Internati.pdf`, ResearchGate `341746025`) | Tests `$MFT`, `$LogFile`, `$UsnJrnl`, `.lnk`, Prefetch, EVTX against Timestomp/SetMACE/nTimestomp; concludes timestamps alone cannot reliably withstand manipulation | Primary PDF for tested Windows builds and artifact-specific findings | `UNVERIFIED` |
| **E-02** | **WMI & EVTX Default Buffer Caps + WMI Persistence** `[66, 98, 99]` | Forensic Focus `[66]`, SANS blog `[98]`, ReverseEngineering.app `[99]` | Claims default EVTX caps of `1 MB` (WMI-Activity), `15 MB` (PowerShell), `64 MB` (Sysmon), plus `OBJECTS.DATA` CIM persistence structure | Microsoft docs / clean Windows VM defaults to verify exact buffer sizes and WMI namespaces | `UNVERIFIED` |
| **E-03** | **Amcache `FileId` & Deleted Binaries** `[36, 71]` | AmcacheParser guides (`amcacheparser.com/en/blog/amcacheparser-complete-guide`, `amcache-deleted-files`) | Claims `FileId` hashes `"0000" + SHA-1` of the **leading 31 MiB** (not full files `> 31 MiB`) and Compatibility Appraiser runs roughly daily | Empirical test on controlled Windows 10/11 files `> 31 MiB` | `UNVERIFIED` |
| **E-04** | **Prefetch SCCA Hashing & Failure Modes** `[70, 77, 79, 86, 108]` | Cybaverse `[70]`, Hejely Lab `[77]`, TrustedSec `[79]`, hiddenillusion `[86]`, ResearchGate `394940091` | Notes `EnablePrefetcher = 0` on Server, `1,024` rollover, ~10s window, `.pf` creation even on failed launch, and command-line folding for `svchost`/`rundll32`/`dllhost`/`mmc` + `/prefetch:[0-8]` | Empirical Windows 10/11 build tests + primary docs (keeps hosting-app SCCA hashing `EXPERIMENTAL` in `REFGRAPH_SPEC.md`) | `UNVERIFIED` |
| **E-05** | **Scheduled Task Tampering & Comburglar** `[73–76]` | The DFIR Report `[73]`, Purple Team `[74]`, ScheduledTasksParser `[75]`, BHIS `[76]` | Documents COM hijack `TaskCache` + `InprocServer32` + `Wow6432Node`, XML-absent tasks, stripped SDs, and `ie4uinit.exe` `.inf` chains | Primary case write-ups and clean Windows validation | `UNVERIFIED` |
| **E-06** | **MFT Reference Resolution & Self-Deleting Dropper Tradeoff** `[81, 82, 90, 93]` | RAT In Mi Kitchen `[81]`, Lexfo `[82]`, w4rri0r `[90]`, Windows Registry Forensics book `[93]` | Describes MFT sequence increment on deletion, Cobalt Strike SMB Beacon self-deletion traces, Wow64 redirection, and `Parameters\ServiceDll` | Verify NTFS sequence-number behavior on Windows 10/11 and ServiceDll hive schema | `UNVERIFIED` |
| **E-07** | **ForTrace / ForTrace++** `[126–130]` | DFRWS EU 2022 / 2024 / FSI 2025 (`2022_eu_ForTrace_presentation.pdf`, `2024_dfrws_eu_wolf_agent-less_fortrace.pdf`, `dfrws.org/.../2025...pdf`) | Hypervisor-driven forensic dataset generation avoiding client-side agent artifacts; relevant background comparison for clean vs dirty benign controls | Check PDFs for KVM/QEMU orchestration patterns and synthetic artifact fidelity | `UNVERIFIED` |
| **E-08** | **ADFIR (2025) & *The Stolen Szechuan Sauce*** `[97, 132–134]` | ADFIR PDF `[97]` + walkthroughs (`walshcat`, `Herdomain`, `iblue.team`) | Synthetic + CTF E01 corpus (`DC01` Server 2012 R2 w/ `$MFT` `111,850` / `$J` `82,085` + Win10 desktop); noted as lacking unified machine-readable labels | Inspect dataset docs & license for post-final qualitative case study suitability (`OD-V2-19`) | `UNVERIFIED` |
| **E-09** | **NIST CFReDS & Magnet CTF** `[131]` | NIST (`https://cfreds.nist.gov/all`) | Standard public DFIR disk challenge images reserved strictly for post-v2-final qualitative inspection (`OD-V2-19`) with zero tuning | Specific scenario selection and license checks deferred until after v2 `--final` | `UNVERIFIED` |
