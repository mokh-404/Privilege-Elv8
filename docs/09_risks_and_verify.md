# 09. Verified Facts, Open Verification Items, and Risks — Rev 2

## 1. Verified against primary sources (this revision)

| Claim | Result | Source |
|---|---|---|
| CIC-MalMem-2022 has 58,596 records, 29,298 benign and 29,298 malware | Verified | Carrier et al., ICISSP 2022; UNB CIC page |
| 2,916 malware samples executed in a Windows 10 64-bit VirtualBox VM with 2 GB memory | Verified | Carrier et al. |
| 10 memory dumps per sample execution, 15 seconds apart | Verified | Carrier et al. |
| Benign dumps oversampled with SMOTE to balance classes | Verified | Carrier et al. |
| 3 categories x 5 families = 15 families (names as listed in `04`) | Verified | UNB page; Carrier et al. Table 2 |
| Per-family row counts sum to 29,298 | Checked arithmetically from independently reported counts | Independent papers |
| 57 columns (55 features + `Class` + `Category`) | Reported by independent papers; **confirm on load** | Independent papers |
| Features extracted with Volatility 2.6 and VolMemLyzer-V2 | Verified | Carrier et al. |

## 2. Discrepancies and things not verified

| Item | Note |
|---|---|
| Paper says VolMemLyzer-V2 extracts 58 features; the CSV has 55 | Cite the CSV count; mention the discrepancy |
| 2,916 x 10 = 29,160 vs 29,298 malware dumps | The paper's own numbers differ slightly. Do not state "exactly 10 per sample" |
| `Category` string format in the CSV | Not verified. Inspect real values before writing the parser |
| Whether any column identifies the source sample | Not verified. If one exists, group by sample as well as by family |
| Tiwari et al. (2025) reported numbers (about 0.9999 XGBoost accuracy, neural-network row inconsistencies) | Taken from the uploaded paper in the earlier analysis; re-check the figures against the PDF before quoting |
| DFIR-Chain (Karne et al. 2025) values | Same: re-check against the PDF |
| Kuforiji (2025) | Indexing and citation quality unverified; background only |
| ISO/IEC 27037, 27043; NIST SP 800-61, 800-86; GDPR | Check titles and versions at the primary source |
| EMBER, BODMAS, SOREL-20M, OTRF, EVTX-ATTACK-SAMPLES, Splunk attack_data, MemLabs | Not needed in the 3-day plan; verify if added |
| Atomic Red Team tests and default install path | Verify each chosen test exists and runs offline; verify the default module path before writing the exclusion rule |
| Windows 10 evaluation ISO availability | Windows 10 reached end of support in October 2025; confirm what the Evaluation Center offers |
| Volatility 3 plugin names and symbol requirements | Only if the memory add-on is used |
| Admissibility claims | Not legal advice; confirm with a qualified person |
| Venue acceptance criteria | Read the venue's call for papers |

## 3. Risk register

| ID | Risk | Likelihood (est.) | Impact | Mitigation |
|---|---|---|---|---|
| R1 | No working collector by end of Day 1 | Medium | Critical | Build the collector first; live collection inside the VM; no memory features |
| R2 | Defender or SmartScreen blocks techniques | High | Medium | Narrow documented exclusions; offline-safe techniques; no downloaded tools |
| R3 | Run time per run exceeds plan | Medium | High | Measure on Day 1; cut techniques before variants |
| R4 | Too few positives in the 5 holdout techniques | Medium | High | Add variants for holdout techniques; report wide intervals |
| R5 | Label ambiguity | Medium | High | Provenance log plus diff; human review |
| R6 | Leakage via features or splits | Medium | Critical | Rules in `05` section 8; frozen test set |
| R7 | **Simulation vocabulary leaks into names and command lines** | High | High | DS-09, DS-10, FE-08 assertion |
| R8 | **Benign-drift artifacts not in the attack window** (previous revision's design) | Resolved in Rev 2 | High | Interleaved benign noise (`05` section 4) |
| R9 | Thermal throttling | Medium | Low | Elevate laptop; monitor |
| R10 | Disk fills up | Medium | High | 100 GB headroom; disk guard |
| R11 | Overfitting to simulation artifacts | High | Medium | Vary names, paths and arguments; state limitation |
| R12 | Deep models underperform; professor expects them to win | Medium | Low | Frame as honest comparison; training-size curve; SHAP |
| R13 | PyTorch arms and SHAP take longer than planned | Medium | Medium | Develop on Track B on Day 1; split ML role; flag before downgrading SHAP |
| R14 | Track B scores look saturated on the leaky split | High | Low | Expected; split 2 and the framing handle it |
| R15 | Benign FPR on Track B is optimistic (SMOTE twins) | High | Medium | Cluster-based grouping; print the caveat |
| R16 | One VM profile limits generality | Certain | Medium | State in limitations; second profile stretch |
| R17 | Only 5 held-out techniques | Certain | Medium | Run-level intervals, per-technique table, tentative wording |
| R18 | Scope creep | High | High | Locked decisions and cut list |

## 4. Questions to settle

1. Is the full DFIR-Triage agent usable as the collector, or do we use the minimal one?
2. How many people, and on which days?
3. Is the paper for submission or course credit? (Affects strictness of evaluation and citations.)
4. Exact laptop configuration (CPU, GPU, free disk).
5. After inspecting the CSV: is there a column that identifies the sample?

## 5. What would change the plan

- Solo work: apply the cut list fully; 12 techniques; treat as a case study.
- No working collector: day 1 yields no Track A data; extend to 4 days or fall back to Track B only (weaker fit).
- About 7 days: second profile, memory add-on, red/blue rounds, one more public benchmark.
