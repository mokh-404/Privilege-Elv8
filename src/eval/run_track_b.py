"""Track B evaluation suite (CIC-MalMem-2022): all 5 arms across Split 1 (leaky) and Split 2.

Usage:
    python -m src.eval.run_track_b --inspect
    python -m src.eval.run_track_b --smoke
    python -m src.eval.run_track_b --split1 --split2 [--rotate] [--include-lr]

No model sees Category or Class as input (asserted). Split 1 is labelled LEAKY everywhere.
Split 2 prints the SMOTE-twin benign-FPR caveat and checks for suspiciously perfect scores.
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Callable, Sequence

import numpy as np
import pandas as pd

from src import config
from src.data import cic_malmem, splits
from src.eval import metrics as M
from src.models.autoencoder import DeepAutoencoderArm
from src.models.mlp import TabularMLPArm
from src.models.preprocess import SharedPreprocessor
from src.models.sklearn_models import (
    IsolationForestArm,
    RandomForestArm,
    XGBoostArm,
    build_logistic_regression_arm,
)
from src.utils.repro import get_commit_hash, run_metadata, set_global_seed, write_json


def _build_arm(arm: str, seed: int = config.SEED, max_epochs_override: int | None = None):
    if arm == "rf":
        return RandomForestArm(seed=seed)
    if arm == "xgb":
        return XGBoostArm(seed=seed)
    if arm == "iforest":
        return IsolationForestArm(seed=seed)
    if arm == "mlp":
        extra = {"max_epochs": max_epochs_override} if max_epochs_override is not None else {}
        return TabularMLPArm(seed=seed, **extra)
    if arm == "ae":
        extra = {"max_epochs": max_epochs_override} if max_epochs_override is not None else {}
        return DeepAutoencoderArm(seed=seed, **extra)
    if arm == "lr":
        return build_logistic_regression_arm(seed=seed)
    raise ValueError(f"Unknown model arm: {arm!r}")


def _assert_ev04(X: pd.DataFrame) -> None:
    assert config.CIC_CATEGORY_COL not in X.columns, f"{config.CIC_CATEGORY_COL} leaked into X!"
    assert config.CIC_LABEL_COL not in X.columns, f"{config.CIC_LABEL_COL} leaked into X!"


def _fit_and_score_arm(
    arm_key: str,
    X_df: pd.DataFrame,
    y: np.ndarray,
    feature_cols: list[str],
    train_idx: np.ndarray,
    val_idx: np.ndarray,
    benign_val_idx: np.ndarray,
    test_idx: np.ndarray,
    train_all_idx: np.ndarray | None = None,
    seed: int = config.SEED,
    max_epochs_override: int | None = None,
    save_path: Path | None = None,
) -> dict:
    """Preprocess cleanly (benign-only fit for unsupervised arms), train, and score."""
    _assert_ev04(X_df)
    arm = _build_arm(arm_key, seed=seed, max_epochs_override=max_epochs_override)

    if arm.is_unsupervised:
        fit_idx = train_all_idx if train_all_idx is not None else train_idx
        fit_benign_idx = fit_idx[y[fit_idx] == 0]
        pre = SharedPreprocessor(categorical=[], numeric=feature_cols, binary=[]).fit(X_df.iloc[fit_benign_idx])
        X_tr = pre.transform(X_df.iloc[fit_benign_idx])
        y_tr = y[fit_benign_idx]
        X_va = pre.transform(X_df.iloc[benign_val_idx])
        y_va = y[benign_val_idx]
    else:
        # MLP uses family-grouped inner val_idx for early stopping; tree/linear arms use train_all_idx
        use_idx = train_idx if arm_key == "mlp" else (train_all_idx if train_all_idx is not None else train_idx)
        pre = SharedPreprocessor(categorical=[], numeric=feature_cols, binary=[]).fit(X_df.iloc[use_idx])
        X_tr = pre.transform(X_df.iloc[use_idx])
        y_tr = y[use_idx]
        X_va = pre.transform(X_df.iloc[val_idx])
        y_va = y[val_idx]

    X_bval = pre.transform(X_df.iloc[benign_val_idx])
    X_te = pre.transform(X_df.iloc[test_idx])

    t0 = time.perf_counter()
    arm.fit(X_tr, y_tr, X_val=X_va, y_val=y_va)
    train_time_s = time.perf_counter() - t0

    t1 = time.perf_counter()
    test_scores = arm.predict_scores(X_te)
    infer_elapsed = time.perf_counter() - t1
    infer_per_1k = (infer_elapsed / max(1, len(X_te))) * 1000.0
    bval_scores = arm.predict_scores(X_bval)

    if save_path is not None:
        arm.save(save_path)

    return {
        "arm": arm_key,
        "arm_name": config.ARM_DISPLAY[arm_key],
        "test_scores": test_scores,
        "bval_scores": bval_scores,
        "train_time_s": float(train_time_s),
        "infer_time_per_1k_s": float(infer_per_1k),
    }


def run_split1(
    X_df: pd.DataFrame,
    y: np.ndarray,
    feature_cols: list[str],
    arms: Sequence[str],
    seed: int = config.SEED,
    max_epochs_override: int | None = None,
    models_dir: Path | None = None,
) -> pd.DataFrame:
    """Split 1: stratified 80/20 (LEAKY reproduction of literature setup)."""
    sp = splits.track_b_split1_leaky(y, seed=seed)
    commit = get_commit_hash()
    rows = []
    for arm_key in arms:
        save_p = (models_dir / f"track_b_split1_{arm_key}.bin") if models_dir else None
        res = _fit_and_score_arm(
            arm_key, X_df, y, feature_cols,
            train_idx=sp["train_idx"], val_idx=sp["val_idx"],
            benign_val_idx=sp["benign_val_idx"], test_idx=sp["test_idx"],
            train_all_idx=sp["train_all_idx"], seed=seed,
            max_epochs_override=max_epochs_override, save_path=save_p,
        )
        y_te = y[sp["test_idx"]]
        s_te = res["test_scores"]
        if arm_key in config.UNSUPERVISED_ARMS:
            thresh = M.threshold_at_fpr(res["bval_scores"], 0.05)
        else:
            thresh = 0.5
        rows.append({
            "arm": arm_key,
            "arm_name": res["arm_name"],
            "split_note": sp["split_note"],
            "pr_auc": M.pr_auc(y_te, s_te),
            "roc_auc": M.roc_auc(y_te, s_te),
            "accuracy": M.accuracy_at_threshold(y_te, s_te, thresh),
            "f1": M.f1_at_threshold(y_te, s_te, thresh),
            "threshold_used": float(thresh),
            "train_time_s": res["train_time_s"],
            "infer_time_per_1k_s": res["infer_time_per_1k_s"],
            "n_train": int(len(sp["train_all_idx"])),
            "n_test": int(len(sp["test_idx"])),
            "seed": seed,
            "commit": commit,
        })
    return pd.DataFrame(rows)


def run_split2(
    X_df: pd.DataFrame,
    y: np.ndarray,
    categories: pd.Series,
    families: pd.Series,
    feature_cols: list[str],
    arms: Sequence[str],
    held_out_families: Sequence[str] | None = None,
    rotation_idx: int | str = "single",
    seed: int = config.SEED,
    draw_seed: int = config.TRACK_B_HOLDOUT_DRAW_SEED,
    kmeans_seed: int = config.TRACK_B_KMEANS_SEED,
    max_epochs_override: int | None = None,
    models_dir: Path | None = None,
) -> pd.DataFrame:
    """Split 2: family-grouped holdout (3 unseen families) + clustered benign."""
    sp = splits.track_b_split2_family_grouped(
        X_df, y, categories, families,
        held_out_families=held_out_families,
        draw_seed=draw_seed, kmeans_seed=kmeans_seed,
    )
    commit = get_commit_hash()
    y_te = y[sp["test_idx"]]
    rows = []
    for arm_key in arms:
        save_p = (models_dir / f"track_b_split2_rot{rotation_idx}_{arm_key}.bin") if models_dir else None
        res = _fit_and_score_arm(
            arm_key, X_df, y, feature_cols,
            train_idx=sp["train_idx"], val_idx=sp["val_idx"],
            benign_val_idx=sp["benign_val_idx"], test_idx=sp["test_idx"],
            train_all_idx=sp["train_all_malware_idx"], seed=seed,
            max_epochs_override=max_epochs_override, save_path=save_p,
        )
        s_te = res["test_scores"]
        score_pr = M.pr_auc(y_te, s_te)
        if score_pr >= 0.9999:
            print(f"[WARNING] Split 2 arm {arm_key} reached PR-AUC={score_pr:.6f}; inspect for leakage!")
        rec = {
            "arm": arm_key,
            "arm_name": res["arm_name"],
            "rotation": rotation_idx,
            "held_out_families": "|".join(sp["held_out_families"]),
            "pr_auc": score_pr,
            "roc_auc": M.roc_auc(y_te, s_te),
            "train_time_s": res["train_time_s"],
            "infer_time_per_1k_s": res["infer_time_per_1k_s"],
            "n_train": int(len(sp["train_all_malware_idx"])),
            "n_benign_val": int(len(sp["benign_val_idx"])),
            "n_test": int(len(sp["test_idx"])),
            "caveat": sp["caveat"],
            "seed": seed,
            "draw_seed": draw_seed,
            "kmeans_seed": kmeans_seed,
            "commit": commit,
        }
        for fpr_t in config.TRACK_B_FPR_TARGETS:
            t = M.threshold_at_fpr(res["bval_scores"], fpr_t)
            rec[f"unseen_recall_at_fpr_{fpr_t}"] = M.recall_at_threshold(y_te, s_te, t)
            rec[f"test_fpr_at_target_{fpr_t}"] = M.fpr_at_threshold(y_te, s_te, t)
        rows.append(rec)
    return pd.DataFrame(rows)


def make_synthetic_track_b(n_rows: int = 1000, seed: int = config.SEED) -> tuple[pd.DataFrame, np.ndarray, pd.Series, list[str]]:
    """Synthetic 55-feature dataset matching CIC-MalMem-2022 structure for --smoke only."""
    rng = np.random.default_rng(seed)
    n_ben = n_rows // 2
    n_mal = n_rows - n_ben
    n_feat = 55
    feature_cols = [f"feat_{i:02d}" for i in range(n_feat)]

    # Create clustered benign + family-offset malware rows
    centers = rng.normal(0.0, 2.0, size=(20, n_feat))
    b_cid = rng.integers(0, 20, size=n_ben)
    X_b = centers[b_cid] + rng.normal(0.0, 0.4, size=(n_ben, n_feat))

    cat_names = ["Ransomware", "Spyware", "Trojan"]
    fam_names = {
        "Ransomware": ["Conti", "MAZE", "Pysa", "Ako", "Shade"],
        "Spyware": ["180Solutions", "Coolwebsearch", "Gator", "Transponder", "TIBS"],
        "Trojan": ["Zeus", "Emotet", "Refroso", "Scar", "Reconyc"],
    }
    fam_pairs = [(c, f) for c in cat_names for f in fam_names[c]]
    fam_offsets = rng.normal(1.2, 0.8, size=(len(fam_pairs), n_feat))
    m_assign = np.arange(n_mal) % len(fam_pairs)
    X_m = fam_offsets[m_assign] + rng.normal(0.0, 0.6, size=(n_mal, n_feat))

    X_arr = np.vstack([X_b, X_m])
    y = np.concatenate([np.zeros(n_ben, dtype=int), np.ones(n_mal, dtype=int)])
    raw_cats = ["Benign"] * n_ben + [f"{fam_pairs[i][0]}-{fam_pairs[i][1]}" for i in m_assign]
    X_df = pd.DataFrame(X_arr, columns=feature_cols)
    return X_df, y, pd.Series(raw_cats), feature_cols


def _smoke_parse_category(series: pd.Series) -> tuple[pd.Series, pd.Series]:
    cats, fams = [], []
    for v in series.astype(str):
        if v == "Benign":
            cats.append("Benign")
            fams.append("Benign")
        else:
            c, f = v.split("-", 1)
            cats.append(c)
            fams.append(f)
    return pd.Series(cats, index=series.index), pd.Series(fams, index=series.index)


def run_pipeline(
    X_df: pd.DataFrame,
    y: np.ndarray,
    raw_category: pd.Series,
    feature_cols: list[str],
    arms: Sequence[str],
    do_split1: bool = True,
    do_split2: bool = True,
    do_rotate: bool = False,
    category_parser: Callable[[pd.Series], tuple[pd.Series, pd.Series]] = cic_malmem.parse_category,
    out_tables_dir: Path = config.TABLES_DIR,
    logs_dir: Path = config.LOGS_DIR,
    models_dir: Path | None = None,
    seed: int = config.SEED,
    max_epochs_override: int | None = None,
    is_smoke: bool = False,
    csv_path: Path | None = None,
) -> dict[str, pd.DataFrame]:
    """Execute requested Track B splits, write tables + metadata JSON, and return DataFrames."""
    set_global_seed(seed)
    _assert_ev04(X_df)
    out_tables_dir = Path(out_tables_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, pd.DataFrame] = {}

    if do_split1:
        df1 = run_split1(
            X_df, y, feature_cols, arms, seed=seed,
            max_epochs_override=max_epochs_override, models_dir=models_dir,
        )
        p1 = out_tables_dir / ("track_b_split1_smoke.csv" if is_smoke else "track_b_split1.csv")
        df1.to_csv(p1, index=False)
        outputs["split1"] = df1
        print(f"Saved Split 1 ({config.TRACK_B_SPLIT1_TAG}) -> {p1}")

    if do_split2 or do_rotate:
        cats, fams = category_parser(raw_category)
        cic_malmem.validate_parsed_families(cats, fams, y)
        print(config.TRACK_B_CAVEAT)

    if do_split2:
        df2 = run_split2(
            X_df, y, cats, fams, feature_cols, arms,
            seed=seed, max_epochs_override=max_epochs_override, models_dir=models_dir,
        )
        p2 = out_tables_dir / ("track_b_split2_smoke.csv" if is_smoke else "track_b_split2.csv")
        df2.to_csv(p2, index=False)
        outputs["split2"] = df2
        print(f"Saved Split 2 -> {p2}")

    if do_rotate:
        rot_frames = []
        for idx, held_out in enumerate(splits.track_b_rotations(cats, fams, y)):
            rot_frames.append(run_split2(
                X_df, y, cats, fams, feature_cols, arms,
                held_out_families=held_out, rotation_idx=idx,
                seed=seed, max_epochs_override=max_epochs_override, models_dir=models_dir,
            ))
        dfr = pd.concat(rot_frames, ignore_index=True)
        pr = out_tables_dir / ("track_b_split2_rotations_smoke.csv" if is_smoke else "track_b_split2_rotations.csv")
        dfr.to_csv(pr, index=False)
        outputs["rotations"] = dfr
        print(f"Saved Split 2 rotations -> {pr}")

        agg_cols = ["pr_auc", "roc_auc"] + [f"unseen_recall_at_fpr_{f}" for f in config.TRACK_B_FPR_TARGETS]
        summary = (
            dfr.groupby(["arm", "arm_name"], sort=False)[agg_cols]
            .agg(["mean", "std", "min", "max"])
        )
        summary.columns = [f"{col}_{stat}" for col, stat in summary.columns]
        summary = summary.reset_index()
        summary["n_rotations"] = int(dfr["rotation"].nunique())
        summary["caveat"] = config.TRACK_B_CAVEAT
        summary["seed"] = seed
        summary["draw_seed"] = config.TRACK_B_HOLDOUT_DRAW_SEED
        summary["kmeans_seed"] = config.TRACK_B_KMEANS_SEED
        summary["commit"] = get_commit_hash()
        prs = out_tables_dir / (
            "track_b_split2_rotations_summary_smoke.csv" if is_smoke else "track_b_split2_rotations_summary.csv"
        )
        summary.to_csv(prs, index=False)
        outputs["rotations_summary"] = summary
        print(f"Saved Split 2 rotation summary -> {prs}")

    extra_meta = {
        "track": "B",
        "smoke": is_smoke,
        "arms": list(arms),
        "n_rows": int(len(X_df)),
        "n_features": int(len(feature_cols)),
        "splits": list(outputs),
        "draw_seed": config.TRACK_B_HOLDOUT_DRAW_SEED,
        "kmeans_seed": config.TRACK_B_KMEANS_SEED,
    }
    if csv_path is not None and Path(csv_path).exists():
        extra_meta["csv_path"] = str(csv_path)
        extra_meta.update({f"csv_{k}": v for k, v in cic_malmem.csv_hashes(csv_path).items()})
    meta = run_metadata(extra_meta)
    write_json(meta, Path(logs_dir) / f"track_b_{'smoke_' if is_smoke else ''}meta.json")
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Track B (CIC-MalMem-2022) five-arm benchmark.")
    parser.add_argument("--inspect", action="store_true", help="Inspect CSV shape & Category values and exit.")
    parser.add_argument("--csv", type=Path, default=config.CIC_MALMEM_CSV)
    parser.add_argument("--split1", action="store_true", help="Run stratified 80/20 split (LEAKY).")
    parser.add_argument("--split2", action="store_true", help="Run family-grouped holdout split.")
    parser.add_argument("--rotate", action="store_true", help="Run 5-family rotation on Split 2.")
    parser.add_argument("--arms", nargs="+", default=list(config.ARMS), choices=config.ARMS + config.OPTIONAL_ARMS)
    parser.add_argument("--include-lr", action="store_true", help="Also run optional LogisticRegression baseline.")
    parser.add_argument("--out-dir", type=Path, default=config.TABLES_DIR)
    parser.add_argument("--save-models", action="store_true")
    parser.add_argument("--smoke", action="store_true", help="Run end-to-end smoke check on 1,000 synthetic rows.")
    args = parser.parse_args(argv)

    if args.inspect:
        cic_malmem.inspect_csv(args.csv)
        return 0

    arms = list(args.arms)
    if args.include_lr and "lr" not in arms:
        arms.append("lr")

    do_s1, do_s2 = args.split1, args.split2
    if not (do_s1 or do_s2 or args.rotate):
        do_s1, do_s2 = True, True

    if args.smoke:
        X_df, y, raw_cat, fcols = make_synthetic_track_b(1000, seed=config.SEED)
        run_pipeline(
            X_df, y, raw_cat, fcols, arms,
            do_split1=do_s1, do_split2=do_s2, do_rotate=args.rotate,
            category_parser=_smoke_parse_category,
            out_tables_dir=args.out_dir, logs_dir=config.LOGS_DIR,
            models_dir=(config.MODELS_DIR if args.save_models else None),
            max_epochs_override=3, is_smoke=True,
        )
        return 0

    X_df, y, raw_cat, fcols = cic_malmem.load_raw(args.csv, check_shape=True)
    run_pipeline(
        X_df, y, raw_cat, fcols, arms,
        do_split1=do_s1, do_split2=do_s2, do_rotate=args.rotate,
        category_parser=cic_malmem.parse_category,
        out_tables_dir=args.out_dir, logs_dir=config.LOGS_DIR,
        models_dir=(config.MODELS_DIR if args.save_models else None),
        is_smoke=False,
        csv_path=args.csv,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
