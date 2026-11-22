# 02. Feasibility (3 days) and Hardware (ASUS TUF A15, 24 GB RAM) — Rev 2

All durations are planning estimates, not measurements. Re-measure on Day 1.

## 1. Verdict

| Question | Answer |
|---|---|
| Full plan (several public datasets, red/blue rounds, memory dumps, LLM evaluation) in 3 days | **No** |
| **Reduced "Hybrid-lite" plan in 3 days with 3 or more people** | **Yes** |
| Same plan done by one person | Not realistic |
| Runs on the ASUS TUF A15 with 24 GB RAM | **Yes, one VM at a time** |

Rev 2 shifts work from the lab to the modeling side: the lab shrinks to one VM, while the model suite grows (two PyTorch arms, mandatory SHAP, two Track B splits). Net effect: the Day-1 critical path is shorter, and Day 2 and Day 3 are busier for the ML role.

## 2. What is in scope vs cut

| Item | Status | Reason |
|---|---|---|
| Track A: generated dataset, one VM profile, grouped split | **In (core)** | This is the contribution |
| Track B: CIC-MalMem-2022 with two splits | **In** | Small, pre-extracted; no Volatility run needed |
| Random Forest, XGBoost, Isolation Forest, PyTorch MLP, PyTorch autoencoder | **In (mandatory)** | Matches the supervised/unsupervised x ML/DL matrix |
| SHAP for tree models and MLP | **In (mandatory)** | Needed to explain why one family wins |
| Logistic regression | Optional | Five-line sanity baseline |
| Second VM profile | Stretch (Day 2) | Day-1 provisioning of two VMs is the main schedule risk |
| Red/blue rounds | Stretch | Needs repeated runs and retraining |
| Memory dumps from the lab + Volatility 3 | Cut | Slow per run; memory is covered by Track B |
| EMBER / BODMAS / SOREL-20M, event-log datasets | Cut | Separate pipelines, large downloads |
| Live malware | Out | Safety and the proposal |
| LLM report evaluation | Cut | Not needed for the model comparison |

## 3. Run budget (single VM)

| Plan | Techniques | Variants | Runs | Sequential time (estimate) |
|---|---|---|---|---|
| MVP | 15 (10 dev + 5 holdout) | 3 | 45 | about 3 to 4.5 h |
| Target | 18 (12 dev + 5 holdout, plus 1 spare) | 3 to 4 | up to 65 | about 4.5 to 6.5 h |

One run = revert snapshot, boot, interleaved benign and attack steps, collect, shut down = about 4 to 6 minutes (estimate). With one VM, runs are sequential, which is fine for an unattended Day-1 evening start. Do not add a parallel VM at the 6 to 8 GB sizing.

## 4. Hardware budget

The laptop's exact CPU, GPU and free disk are not confirmed. Run the Day 0 checklist.

### RAM (24 GB)

| Consumer | Estimated RAM |
|---|---|
| Windows host, idle plus tools | 5 to 7 GB |
| Lab VM (one) | 6 to 8 GB |
| Python training (pandas, sklearn, XGBoost, PyTorch CPU) | 2 to 4 GB |
| Llama 3 8B Q4 via Ollama (optional) | 5 to 6 GB |

- VM + training: about 13 to 19 GB. Fits.
- VM + training + LLM together: about 18 to 25 GB. **Do not run the LLM during VM runs or training.**
- Work that does not need the VM (Track B, model development on early data) can run while the VM is idle, but not while the VM is running a long unattended batch if RAM is under pressure. Watch the host's memory use.

### Disk

- Minimum: **70 to 80 GB free on SSD**, with one 60 GB VM disk (dynamically allocated), no memory dumps retained, one base VM and linked clones.
- Recommended: **about 100 GB free** for headroom (ISO files, installers, Atomic prerequisites, snapshots, datasets, model outputs). This is my suggestion, not a measured need.
- Delete any memory dumps after feature extraction (if the stretch add-on is ever used).

### CPU and GPU

- Random Forest, XGBoost, Isolation Forest, and both PyTorch models train on CPU on data of this size (Track B has 58,596 rows x 55 features; Track A is expected to be tens of thousands to a few hundred thousand rows after deduplication, an estimate). No GPU is required.
- SHAP: TreeExplainer is fast. For the MLP use a background sample of about 100 rows and explain a few hundred rows, because Kernel-style methods are slow.
- A GPU, if present, only helps the optional LLM and optional large training runs.
- AMD CPU: VirtualBox, VMware Workstation and Hyper-V all work, but SVM must be enabled in BIOS.

### Day 0 checklist (15 to 30 minutes)

- [ ] Virtualization enabled (Task Manager > Performance > CPU)
- [ ] At least 100 GB free on SSD (70 to 80 GB absolute minimum)
- [ ] Hypervisor installed (VMware Workstation or VirtualBox)
- [ ] Windows 10/11 evaluation ISO available (client Windows, because Prefetch is on by default there). Check that the ISO is still offered, since Windows 10 reached end of support in October 2025.
- [ ] Python 3.10+ environment: pandas, scikit-learn, xgboost, torch (CPU is fine), shap, matplotlib, pyarrow
- [ ] Invoke-AtomicRedTeam and atomics downloaded while online
- [ ] Power plan High Performance, charger connected, sleep disabled, laptop elevated for cooling
- [ ] CIC-MalMem-2022 CSV downloaded and `assert df.shape == (58596, 57)` passes

## 5. Biggest threats to the timeline

1. No working collector by end of Day 1.
2. Defender or SmartScreen interfering with the simulated techniques.
3. Labeling ambiguity (see playbook).
4. Too few attacker-induced rows in the 5 held-out techniques for stable metrics.
5. PyTorch arms taking longer than expected to debug (mitigation: start them on Track B on Day 1, where data is ready).
6. Scope creep.

See `06_schedule_3days.md` and `09_risks_and_verify.md`.
