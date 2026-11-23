"""v2 multi-control, Sysmon causal process-tree, dormant-manifest & quarantine labeler (Step C.4 / IMP-03)."""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from typing import Any, Mapping, Sequence

import pandas as pd

from src import config
from src.data import sanitize, splits
from src.data.labeler import stable_content_hash
from src.v2.offline_extractor import is_v2_harness_footprint_record


AMBIGUOUS_LABEL = "ambiguous_unattributed"
V2_LABEL_VALUES: tuple[str, ...] = (
    config.POSITIVE_LABEL,
    "benign_drift",
    "baseline",
    AMBIGUOUS_LABEL,
)


def drop_v2_harness_footprint(
    df: pd.DataFrame,
    log_path: Any = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Deterministically filter both v1 runner footprint and v2 harness artifacts (`\\DFIR-StageRunner`,
    `C:\\DFIR-Bootstrap\\*`, `C:\\collector_out_parity\\*`, `Sysmon64`/`SysmonDrv`).

    Never touches frozen v1 `results/logs/runner_footprint_dropped.csv` unless explicitly passed in `log_path`.
    """
    if len(df) == 0:
        return df.copy(), pd.DataFrame(columns=["run_id", "artifact_type", "artifact_key", "name", "path", "drop_reason"])

    kept_v1, dropped_v1 = sanitize.drop_runner_footprint(df.copy(), log_path=None)
    v2_reasons = [is_v2_harness_footprint_record(rec) for rec in kept_v1.to_dict(orient="records")]
    v2_mask = pd.Series([r is not None for r in v2_reasons], index=kept_v1.index)

    dropped_v2 = kept_v1[v2_mask].copy()
    if len(dropped_v2):
        dropped_v2["drop_reason"] = [r for r in v2_reasons if r is not None]
    kept = kept_v1[~v2_mask].reset_index(drop=True)

    cols = [c for c in ("run_id", "artifact_type", "artifact_key", "name", "path", "drop_reason") if c in df.columns or c == "drop_reason"]
    all_dropped_parts = []
    if len(dropped_v1):
        all_dropped_parts.append(dropped_v1[[c for c in cols if c in dropped_v1.columns]])
    if len(dropped_v2):
        all_dropped_parts.append(dropped_v2[[c for c in cols if c in dropped_v2.columns]])
    all_dropped = (
        pd.concat(all_dropped_parts, ignore_index=True)
        if all_dropped_parts
        else pd.DataFrame(columns=["run_id", "artifact_type", "artifact_key", "name", "path", "drop_reason"])
    )

    if log_path is not None:
        from pathlib import Path
        lp = Path(log_path)
        if lp.resolve() == config.RUNNER_FOOTPRINT_LOG_CSV.resolve():
            raise ValueError("Refusing to overwrite frozen v1 RUNNER_FOOTPRINT_LOG_CSV from v2 labeler")
        lp.parent.mkdir(parents=True, exist_ok=True)
        all_dropped.to_csv(lp, index=False)

    return kept, all_dropped


def build_multi_control_baseline(control_dfs: Sequence[pd.DataFrame]) -> dict[str, Any]:
    """Build union baseline content-hash index and per-key boot frequency across control boots."""
    hash_index: dict[str, set[str]] = {}
    boot_counts: Counter[str] = Counter()
    n_boots = 0
    for cdf in control_dfs:
        if cdf is None or len(cdf) == 0:
            continue
        n_boots += 1
        seen_in_boot: set[str] = set()
        for _, row in cdf.iterrows():
            akey = str(row["artifact_key"]).lower()
            hash_index.setdefault(akey, set()).add(stable_content_hash(row))
            seen_in_boot.add(akey)
        for k in seen_in_boot:
            boot_counts[k] += 1
    return {
        "hash_index": hash_index,
        "boot_counts": dict(boot_counts),
        "n_control_boots": n_boots,
    }


def _norm_s(val: Any) -> str:
    return "" if val is None or (isinstance(val, float) and pd.isna(val)) else str(val).strip().lower()


def trace_sysmon_process_tree(
    sysmon_events: Sequence[Mapping[str, Any]],
    root_guids: Sequence[str] = (),
    root_pids: Sequence[int] = (),
    root_hashes: Sequence[str] = (),
) -> dict[str, Any]:
    """Trace transitive causal process/file/registry/task/WMI descendants from root malware/scheduler processes."""
    seed_guids = {_norm_s(g) for g in root_guids if _norm_s(g)}
    seed_pids = {int(p) for p in root_pids if p is not None and not pd.isna(p)}
    seed_hashes = {_norm_s(h) for h in root_hashes if _norm_s(h)}

    tree_guids: set[str] = set(seed_guids)
    tree_pids: set[int] = set(seed_pids)
    guid_to_root: dict[str, str] = {g: g for g in seed_guids}
    attributed_paths: set[str] = set()
    attributed_reg_keys: set[str] = set()
    attributed_artifact_keys: set[str] = set()
    target_to_root: dict[str, str] = {}

    events = list(sysmon_events)
    changed = True
    while changed:
        changed = False
        for ev in events:
            eid = int(ev.get("event_id") or 0)
            pguid = _norm_s(ev.get("process_guid"))
            par_guid = _norm_s(ev.get("parent_process_guid"))
            pid = ev.get("pid")
            ppid = ev.get("ppid")
            hashes_str = _norm_s(ev.get("hashes") or ev.get("file_sha256"))

            if eid == 1:  # ProcessCreate
                matched_root = None
                if pguid and pguid in tree_guids:
                    matched_root = guid_to_root.get(pguid, pguid)
                elif par_guid and par_guid in tree_guids:
                    matched_root = guid_to_root.get(par_guid, par_guid)
                elif ppid is not None and int(ppid) in tree_pids:
                    matched_root = par_guid or f"pid:{int(ppid)}"
                elif seed_hashes and any(sh in hashes_str for sh in seed_hashes):
                    matched_root = pguid or f"sha:{next(iter(seed_hashes))[:12]}"

                if matched_root is not None:
                    if pguid and pguid not in tree_guids:
                        tree_guids.add(pguid)
                        guid_to_root[pguid] = matched_root
                        changed = True
                    if pid is not None and int(pid) not in tree_pids:
                        tree_pids.add(int(pid))
                        changed = True
                    img = _norm_s(ev.get("image") or ev.get("target_path"))
                    if img:
                        attributed_paths.add(img)
                        target_to_root.setdefault(img, matched_root)

            elif eid in (8, 25):  # CreateRemoteThread / ProcessTampering
                src_g = _norm_s(ev.get("source_process_guid")) or pguid
                tgt_g = _norm_s(ev.get("target_process_guid"))
                if src_g in tree_guids:
                    mroot = guid_to_root.get(src_g, src_g)
                    if tgt_g and tgt_g not in tree_guids:
                        tree_guids.add(tgt_g)
                        guid_to_root[tgt_g] = mroot
                        changed = True
                    timg = _norm_s(ev.get("target_image"))
                    if timg:
                        attributed_paths.add(timg)
                        target_to_root.setdefault(timg, mroot)

    for ev in events:
        eid = int(ev.get("event_id") or 0)
        pguid = _norm_s(ev.get("process_guid"))
        pid = ev.get("pid")
        in_tree = (pguid in tree_guids) or (pid is not None and int(pid) in tree_pids)
        if not in_tree:
            continue
        mroot = guid_to_root.get(pguid, pguid or (f"pid:{int(pid)}" if pid is not None else ""))
        if eid in (1, 11):  # FileCreate / Image
            for fld in ("target_filename", "target_path", "image"):
                val = _norm_s(ev.get(fld))
                if val:
                    attributed_paths.add(val)
                    target_to_root.setdefault(val, mroot)
        elif eid in (12, 13, 14):  # RegistryEvent
            tobj = _norm_s(ev.get("target_object"))
            if tobj:
                attributed_reg_keys.add(tobj)
                target_to_root.setdefault(tobj, mroot)
        elif eid in (19, 20, 21):  # WmiEvent
            ak = _norm_s(ev.get("artifact_key"))
            if ak:
                attributed_artifact_keys.add(ak)
                target_to_root.setdefault(ak, mroot)
        ak_ev = _norm_s(ev.get("artifact_key"))
        if ak_ev:
            attributed_artifact_keys.add(ak_ev)
            target_to_root.setdefault(ak_ev, mroot)

    return {
        "tree_guids": sorted(tree_guids),
        "tree_pids": sorted(tree_pids),
        "attributed_paths": sorted(attributed_paths),
        "attributed_reg_keys": sorted(attributed_reg_keys),
        "attributed_artifact_keys": sorted(attributed_artifact_keys),
        "target_to_root": target_to_root,
    }


def _attach_v2_provenance(
    df: pd.DataFrame,
    run_id: str,
    sample_meta: Mapping[str, Any] | None,
    execution_state: str,
    attribution_methods: Sequence[str],
    attribution_confs: Sequence[str],
    root_guids: Sequence[str | None],
) -> pd.DataFrame:
    meta = dict(sample_meta or {})
    out = df.copy()
    out["run_id"] = str(run_id)
    out["schema_version"] = "v2"
    out["sample_sha256"] = meta.get("sample_sha256")
    out["sample_family"] = meta.get("sample_family")
    out["sample_category"] = meta.get("sample_category")
    out["sample_source"] = meta.get("sample_source")
    out["execution_state"] = execution_state
    out["run_duration_s"] = meta.get("run_duration_s")
    out["detonation_exit_status"] = meta.get("detonation_exit_status")
    out["process_tree_root_guid"] = list(root_guids)
    out["attribution_method"] = list(attribution_methods)
    out["attribution_confidence"] = list(attribution_confs)
    out["packer_cluster"] = meta.get("packer_cluster")
    out["label_review_status"] = meta.get("label_review_status", "pending")
    out["stratum"] = execution_state
    out["pair_group_id"] = meta.get("pair_group_id") or meta.get("sample_sha256")
    return out


def label_executed_run(
    run_df: pd.DataFrame,
    baseline_index: Mapping[str, Any],
    sysmon_events: Sequence[Mapping[str, Any]],
    run_id: str,
    malware_root_guids: Sequence[str] = (),
    malware_root_pids: Sequence[int] = (),
    malware_root_hashes: Sequence[str] = (),
    benign_scheduler_guids: Sequence[str] = (),
    benign_scheduler_pids: Sequence[int] = (),
    benign_idle_keys: frozenset[str] | set[str] = frozenset(),
    sample_meta: Mapping[str, Any] | None = None,
    runner_log_path: Any = None,
    sanitization_report: Any = None,
) -> pd.DataFrame:
    """Label an executed VM run via multi-control baseline diff + Sysmon process tree + ambiguous quarantine."""
    if len(run_df) == 0:
        return run_df.copy()

    df, _ = drop_v2_harness_footprint(run_df.copy(), log_path=runner_log_path)
    sanitize.assert_clean(df, report_path=sanitization_report)

    hash_idx = baseline_index["hash_index"] if "hash_index" in baseline_index else baseline_index
    mal_tree = trace_sysmon_process_tree(
        sysmon_events, root_guids=malware_root_guids, root_pids=malware_root_pids, root_hashes=malware_root_hashes
    )
    ben_tree = trace_sysmon_process_tree(
        sysmon_events, root_guids=benign_scheduler_guids, root_pids=benign_scheduler_pids
    )
    mal_hashes_set = {_norm_s(h) for h in malware_root_hashes if _norm_s(h)}
    ben_idle_low = {str(k).lower() for k in benign_idle_keys}

    labels, reasons, methods, confs, rguids, launchers = [], [], [], [], [], []
    for _, row in df.iterrows():
        akey = _norm_s(row.get("artifact_key"))
        rpath = _norm_s(row.get("path"))
        regk = _norm_s(row.get("registry_key"))
        rsha = _norm_s(row.get("file_sha256"))
        chash = stable_content_hash(row)

        if akey in hash_idx and chash in hash_idx[akey]:
            labels.append("baseline")
            reasons.append("multi_control_baseline_unchanged")
            methods.append("baseline_hash_match")
            confs.append("high")
            rguids.append(None)
            launchers.append("baseline")
            continue

        # 1. Malware process-tree attribution
        matched_mal_root = (
            mal_tree["target_to_root"].get(akey)
            or mal_tree["target_to_root"].get(rpath)
            or (mal_tree["target_to_root"].get(regk) if regk else None)
            or (next((v for rk, v in mal_tree["target_to_root"].items() if regk and rk.startswith(regk + "\\")), None))
        )
        if matched_mal_root or (rsha and rsha in mal_hashes_set):
            labels.append(config.POSITIVE_LABEL)
            reasons.append("sysmon_process_tree_attribution")
            methods.append("process_tree_etw")
            confs.append("high")
            rguids.append(matched_mal_root or (malware_root_guids[0] if malware_root_guids else "sha256_match"))
            launchers.append("attack")
            continue

        # 2. Benign scheduler tree OR known multi-control clean idle catalog
        matched_ben_root = (
            ben_tree["target_to_root"].get(akey)
            or ben_tree["target_to_root"].get(rpath)
            or ben_tree["target_to_root"].get(regk)
        )
        if matched_ben_root:
            labels.append("benign_drift")
            reasons.append("benign_scheduler_tree_attribution")
            methods.append("benign_scheduler_tree")
            confs.append("high")
            rguids.append(matched_ben_root)
            launchers.append("benign")
            continue

        if akey in ben_idle_low:
            labels.append("benign_drift")
            reasons.append("verified_clean_idle_drift")
            methods.append("clean_idle_catalog")
            confs.append("medium")
            rguids.append(None)
            launchers.append("os_drift")
            continue

        # 3. Unattributed residual MUST go to ambiguous_unattributed (never silently benign_drift)
        labels.append(AMBIGUOUS_LABEL)
        reasons.append("unattributed_diff_quarantined")
        methods.append("unattributed")
        confs.append("low")
        rguids.append(None)
        launchers.append("unattributed")

    df[config.LABEL_COL] = labels
    df["label_reason"] = reasons
    df["launcher"] = launchers
    return _attach_v2_provenance(
        df, run_id=run_id, sample_meta=sample_meta, execution_state="executed",
        attribution_methods=methods, attribution_confs=confs, root_guids=rguids,
    )


def label_dormant_run(
    run_df: pd.DataFrame,
    baseline_index: Mapping[str, Any],
    staged_manifest: Sequence[Mapping[str, Any]],
    run_id: str,
    sysmon_events: Sequence[Mapping[str, Any]] = (),
    benign_idle_keys: frozenset[str] | set[str] = frozenset(),
    sample_meta: Mapping[str, Any] | None = None,
    runner_log_path: Any = None,
    sanitization_report: Any = None,
) -> pd.DataFrame:
    """Label a dormant (pre-execution staged) run from its exact staging manifest."""
    if len(run_df) == 0:
        return run_df.copy()

    df, _ = drop_v2_harness_footprint(run_df.copy(), log_path=runner_log_path)
    sanitize.assert_clean(df, report_path=sanitization_report)

    hash_idx = baseline_index["hash_index"] if "hash_index" in baseline_index else baseline_index
    staged_map = {
        (_norm_s(m["staged_path"]), _norm_s(m["sample_sha256"])): dict(m)
        for m in staged_manifest
        if m.get("staged_path") and m.get("sample_sha256")
    }
    staged_shas = {sha for _, sha in staged_map}
    # Verify dormant invariant: staged sample must NEVER show Sysmon process creation events
    unexpected_exec = False
    for ev in sysmon_events:
        if int(ev.get("event_id") or 0) == 1:
            eh = _norm_s(ev.get("hashes") or ev.get("file_sha256"))
            ep = _norm_s(ev.get("image") or ev.get("target_path"))
            if any(s in eh for s in staged_shas) or any(sp == ep for sp, _ in staged_map):
                unexpected_exec = True
                break

    ben_idle_low = {str(k).lower() for k in benign_idle_keys}
    labels, reasons, methods, confs, rguids, launchers = [], [], [], [], [], []
    for _, row in df.iterrows():
        akey = _norm_s(row.get("artifact_key"))
        rpath = _norm_s(row.get("path"))
        rsha = _norm_s(row.get("file_sha256"))
        chash = stable_content_hash(row)

        if akey in hash_idx and chash in hash_idx[akey]:
            labels.append("baseline")
            reasons.append("multi_control_baseline_unchanged")
            methods.append("baseline_hash_match")
            confs.append("high")
            rguids.append(None)
            launchers.append("baseline")
            continue

        if (rpath, rsha) in staged_map:
            if unexpected_exec:
                labels.append(AMBIGUOUS_LABEL)
                reasons.append("dormant_run_had_unexpected_execution_trace")
                methods.append("dormant_integrity_violation")
                confs.append("low")
                rguids.append(None)
                launchers.append("unattributed")
            else:
                labels.append(config.POSITIVE_LABEL)
                reasons.append("dormant_staging_manifest_match")
                methods.append("dormant_staging_manifest")
                confs.append("high")
                rguids.append(None)
                launchers.append("attack_dormant")
            continue

        if akey in ben_idle_low:
            labels.append("benign_drift")
            reasons.append("verified_clean_idle_drift")
            methods.append("clean_idle_catalog")
            confs.append("medium")
            rguids.append(None)
            launchers.append("os_drift")
            continue

        labels.append(AMBIGUOUS_LABEL)
        reasons.append("unattributed_dormant_diff_quarantined")
        methods.append("unattributed")
        confs.append("low")
        rguids.append(None)
        launchers.append("unattributed")

    df[config.LABEL_COL] = labels
    df["label_reason"] = reasons
    df["launcher"] = launchers
    return _attach_v2_provenance(
        df, run_id=run_id, sample_meta=sample_meta, execution_state="dormant",
        attribution_methods=methods, attribution_confs=confs, root_guids=rguids,
    )


def assign_v2_splits(
    df: pd.DataFrame,
    blind_test_families: Sequence[str] = (),
    blind_test_clusters: Sequence[str] = (),
    blind_test_benign_runs: Sequence[str] = (),
) -> pd.DataFrame:
    """Assign leakage-proof `split_pool` keeping paired binaries, families & clusters together."""
    out = df.copy()
    bt_fams_seed = {str(f).lower() for f in blind_test_families if f}
    bt_clus_seed = {str(c).lower() for c in blind_test_clusters if c}
    bt_runs = {str(r).lower() for r in blind_test_benign_runs if r}

    # Expand closure across (sample_family, packer_cluster, sample_sha256, pair_group_id)
    pos_mask = out[config.LABEL_COL] == config.POSITIVE_LABEL
    bt_shas: set[str] = set()
    bt_pairs: set[str] = set()
    bt_fams = set(bt_fams_seed)
    bt_clus = set(bt_clus_seed)

    changed = True
    while changed:
        changed = False
        for _, r in out[pos_mask].iterrows():
            if _norm_s(r.get("stratum")) == "emulated":
                continue
            fam = _norm_s(r.get("sample_family"))
            clu = _norm_s(r.get("packer_cluster"))
            sha = _norm_s(r.get("sample_sha256"))
            pid = _norm_s(r.get("pair_group_id"))
            in_bt = (
                (fam and fam in bt_fams)
                or (clu and clu in bt_clus)
                or (sha and sha in bt_shas)
                or (pid and pid in bt_pairs)
            )
            if in_bt:
                for val, target_set in ((fam, bt_fams), (clu, bt_clus), (sha, bt_shas), (pid, bt_pairs)):
                    if val and val not in target_set:
                        target_set.add(val)
                        changed = True

    # Track which run_ids hold blind-test positives so non-ambiguous rows from the same VM run stay together
    bt_pos_runs: set[str] = set()
    for _, r in out[pos_mask].iterrows():
        if _norm_s(r.get("stratum")) == "emulated":
            continue
        fam = _norm_s(r.get("sample_family"))
        clu = _norm_s(r.get("packer_cluster"))
        sha = _norm_s(r.get("sample_sha256"))
        pid = _norm_s(r.get("pair_group_id"))
        if (fam and fam in bt_fams) or (clu and clu in bt_clus) or (sha and sha in bt_shas) or (pid and pid in bt_pairs):
            rid = _norm_s(r.get("run_id"))
            if rid:
                bt_pos_runs.add(rid)

    pools: list[str] = []
    for _, r in out.iterrows():
        lbl = str(r.get(config.LABEL_COL, ""))
        stratum = _norm_s(r.get("stratum"))
        if lbl == AMBIGUOUS_LABEL:
            pools.append("quarantine")
            continue
        if stratum == "emulated":
            pools.append("dev")
            continue
        if lbl == config.POSITIVE_LABEL:
            fam = _norm_s(r.get("sample_family"))
            clu = _norm_s(r.get("packer_cluster"))
            sha = _norm_s(r.get("sample_sha256"))
            pid = _norm_s(r.get("pair_group_id"))
            is_test = (
                (fam and fam in bt_fams)
                or (clu and clu in bt_clus)
                or (sha and sha in bt_shas)
                or (pid and pid in bt_pairs)
            )
            pools.append("test" if is_test else "dev")
        else:
            rid = _norm_s(r.get("run_id"))
            pools.append("test" if (rid in bt_runs or rid in bt_pos_runs) else "dev")

    out["split_pool"] = pools

    # Hard anti-leakage assertions
    dev_sub = out[out["split_pool"] == "dev"]
    test_sub = out[out["split_pool"] == "test"]
    assert not any(_norm_s(s) == "emulated" for s in test_sub.get("stratum", [])), "v1 emulated row in blind test!"

    for col in ("sample_family", "packer_cluster", "sample_sha256", "pair_group_id"):
        if col in out.columns:
            d_pos = {_norm_s(v) for v in dev_sub[dev_sub[config.LABEL_COL] == config.POSITIVE_LABEL][col] if _norm_s(v)}
            t_pos = {_norm_s(v) for v in test_sub[test_sub[config.LABEL_COL] == config.POSITIVE_LABEL][col] if _norm_s(v)}
            assert d_pos.isdisjoint(t_pos), f"Split leakage across {col}: {d_pos & t_pos}"

    dev_ben_runs = {_norm_s(v) for v in dev_sub[dev_sub[config.LABEL_COL] != config.POSITIVE_LABEL]["run_id"] if _norm_s(v)}
    test_ben_runs = {_norm_s(v) for v in test_sub[test_sub[config.LABEL_COL] != config.POSITIVE_LABEL]["run_id"] if _norm_s(v)}
    assert dev_ben_runs.isdisjoint(test_ben_runs), "Benign run_id straddled dev and test!"

    dev_ben_keys = {_norm_s(v) for v in dev_sub[dev_sub[config.LABEL_COL] != config.POSITIVE_LABEL]["artifact_key"] if _norm_s(v)}
    test_ben_keys = {_norm_s(v) for v in test_sub[test_sub[config.LABEL_COL] != config.POSITIVE_LABEL]["artifact_key"] if _norm_s(v)}
    assert dev_ben_keys.isdisjoint(test_ben_keys), "Benign artifact_key straddled dev and test!"

    return out
