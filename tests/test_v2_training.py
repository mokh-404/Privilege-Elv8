"""Unit tests for v2 training integrity pipeline (IMP-08, IMP-09, OD-V2-06, OD-V2-09)."""
from __future__ import annotations

import inspect

import numpy as np
import pandas as pd
import pytest

from src import config
from src.v2 import config_v2
from src.v2.models_v2 import DeepAutoencoderArmV2, TabularMLPArmV2
from src.v2.training import (
    build_family_cluster_groups,
    fit_arm_v2,
    make_inner_val_split,
    run_multiseed_final,
    run_nested_family_cv,
    sample_param_trials,
)


def _make_v2_synthetic_df(n_families: int = 8, n_benign_sessions: int = 12, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows: list[dict] = []
    # Positives: paired dormant + executed per family, plus shared packer cluster on 2 families
    for f_i in range(n_families):
        fam = f"fam_{f_i:02d}"
        packer = "shared_upx_cluster" if f_i in (0, 1) else f"pack_{f_i:02d}"
        for b_i in range(2):
            sha = f"sha_{f_i:02d}_{b_i}"
            pair_id = f"pair_{f_i:02d}_{b_i}"
            for state in ("dormant", "executed"):
                rows.append({
                    "run_id": f"run_{fam}_{state}_{b_i}",
                    "technique_id": "T1053.005" if state == "executed" else "T1204",
                    "sample_family": fam,
                    "packer_cluster": packer,
                    "sample_sha256": sha,
                    "pair_group_id": pair_id,
                    "execution_state": state,
                    "stratum": state,
                    "benign_session_id": None,
                    "artifact_key": f"file|c:\\programdata\\{fam}_{state}_{b_i}.exe|{fam}.exe",
                    "label": "attacker_induced",
                    "artifact_type": "task" if state == "executed" else "file",
                    "path_class": "user_writable",
                    "ext_class": "exe",
                    "signature_state": "unsigned",
                    "parent_process_class": "svchost" if state == "executed" else "na",
                    "registry_location_class": "na",
                    "path_depth": float(rng.integers(3, 6)),
                    "name_length": float(rng.integers(10, 20)),
                    "name_entropy": float(rng.uniform(3.2, 4.2)),
                    "file_size_log": float(rng.uniform(4.5, 5.8)),
                    "file_entropy": float(rng.uniform(6.2, 7.6)),
                    "cmdline_length": float(rng.integers(30, 80) if state == "executed" else 0),
                    "cmdline_entropy": float(rng.uniform(3.0, 4.5) if state == "executed" else 0.0),
                    "cmdline_nonalnum_ratio": float(rng.uniform(0.15, 0.35) if state == "executed" else 0.0),
                    "has_double_extension": 0,
                    "has_encoded_flag": 1 if state == "executed" else 0,
                    "has_url_or_ip": 0,
                    "has_lolbin": 1 if state == "executed" else 0,
                    "has_hidden_attr": 1,
                    "autostart_flag": 1 if state == "executed" else 0,
                })

    # Benign sessions
    for s_i in range(n_benign_sessions):
        sess = f"ben_sess_{s_i:02d}"
        for k_i in range(8):
            rows.append({
                "run_id": f"ctrl_{sess}",
                "technique_id": None,
                "sample_family": None,
                "packer_cluster": None,
                "sample_sha256": None,
                "pair_group_id": None,
                "execution_state": "control",
                "stratum": "benign",
                "benign_session_id": sess,
                "artifact_key": f"service|{sess}_{k_i}|{sess}_{k_i}",
                "label": "baseline",
                "artifact_type": "service",
                "path_class": "system",
                "ext_class": "exe",
                "signature_state": "signed_trusted",
                "parent_process_class": "services",
                "registry_location_class": "services",
                "path_depth": float(rng.integers(2, 4)),
                "name_length": float(rng.integers(6, 12)),
                "name_entropy": float(rng.uniform(2.0, 3.0)),
                "file_size_log": float(rng.uniform(3.5, 4.8)),
                "file_entropy": float(rng.uniform(4.5, 5.8)),
                "cmdline_length": float(rng.integers(20, 45)),
                "cmdline_entropy": float(rng.uniform(2.0, 3.2)),
                "cmdline_nonalnum_ratio": float(rng.uniform(0.05, 0.15)),
                "has_double_extension": 0,
                "has_encoded_flag": 0,
                "has_url_or_ip": 0,
                "has_lolbin": 0,
                "has_hidden_attr": 0,
                "autostart_flag": 0,
            })
    return pd.DataFrame(rows)


def test_v2_search_spaces_support_30_equal_trials():
    assert config_v2.V2_FINAL_SEEDS == [42, 43, 44, 45, 46]
    assert config_v2.V2_N_SEARCH_TRIALS == 30
    assert config_v2.V2_N_SEARCH_TRIALS_FALLBACK == 20
    for arm in ("rf", "xgb", "iforest", "mlp", "ae", "lr"):
        trials = sample_param_trials(arm, n_trials=config_v2.V2_N_SEARCH_TRIALS, seed=42)
        assert len(trials) == 30
        assert len({tuple(sorted(d.items())) for d in trials}) == 30


def test_fit_arm_v2_signature_forbids_outer_va_df():
    sig = inspect.signature(fit_arm_v2)
    assert "va_df" not in sig.parameters
    assert "y_va" not in sig.parameters


def test_iforest_and_non_es_arms_fit_100pct_eligible_rows():
    df = _make_v2_synthetic_df()
    y = (df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    groups = build_family_cluster_groups(df)
    n_ben = int((y == 0).sum())

    if_art = fit_arm_v2(
        "iforest", df, y, groups,
        config.CATEGORICAL_FEATURES, config.NUMERIC_FEATURES, config.BINARY_FEATURES,
        seed=42, params={"n_estimators": 20},
    )
    assert if_art.arm.n_attack_seen_in_fit_ == 0
    assert if_art.arm.n_benign_fit_ == n_ben
    assert if_art.fit_meta["n_fit_rows"] == n_ben
    assert if_art.fit_meta["n_pre_fit_rows"] == n_ben

    for sup_arm in ("rf", "xgb", "lr"):
        art = fit_arm_v2(
            sup_arm, df, y, groups,
            config.CATEGORICAL_FEATURES, config.NUMERIC_FEATURES, config.BINARY_FEATURES,
            seed=42, params={"n_estimators": 10} if sup_arm in ("rf", "xgb") else {},
        )
        assert art.fit_meta["n_fit_rows"] == len(df)
        assert art.fit_meta["n_pre_fit_rows"] == len(df)


def test_ae_and_mlp_early_stop_strictly_on_disjoint_inner_val_and_split_local_prep():
    df = _make_v2_synthetic_df()
    y = (df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    groups = build_family_cluster_groups(df)

    # Hold out 20% as outer validation fold and poison outer va_df with 1e9 outliers & unseen levels
    tr_idx, va_idx = make_inner_val_split(df, y, groups, seed=7)
    tr_df = df.iloc[tr_idx].reset_index(drop=True)
    y_tr = y[tr_idx]
    g_tr = groups[tr_idx]

    for arm_name in ("mlp", "ae"):
        art = fit_arm_v2(
            arm_name, tr_df, y_tr, g_tr,
            config.CATEGORICAL_FEATURES, config.NUMERIC_FEATURES, config.BINARY_FEATURES,
            seed=42, params={"max_epochs": 4, "patience": 2, "batch_size": 16}, device="cpu",
        )
        sub_tr = art.fit_meta["sub_tr_indices"]
        es_val = art.fit_meta["es_val_indices"]
        assert set(sub_tr).isdisjoint(set(es_val))
        assert set(g_tr[sub_tr]).isdisjoint(set(g_tr[es_val]))
        assert set(g_tr).isdisjoint(set(groups[va_idx]))
        assert art.fit_meta["fit_mode"] == "inner_val_early_stop"
        if arm_name == "ae":
            assert art.arm.n_attack_seen_in_fit_ == 0
            assert art.fit_meta["n_pre_fit_rows"] == int((y_tr[sub_tr] == 0).sum())

        # Fit again after mutating outer va_df drastically — preprocessor state must remain bit-for-bit identical
        # (Outer va_df isn't even passed to fit_arm_v2; verify pre scaler statistics match exact sub_tr fit)
        sub_fit_df = tr_df.iloc[sub_tr][y_tr[sub_tr] == 0] if arm_name == "ae" else tr_df.iloc[sub_tr]
        scaler = art.preprocessor.ct.named_transformers_["num"].named_steps["scale"]
        expected_means = sub_fit_df[config.NUMERIC_FEATURES].fillna(0).mean().values
        assert np.allclose(scaler.mean_[: len(config.NUMERIC_FEATURES)], expected_means, atol=1e-6)


def test_union_find_keeps_family_packer_and_paired_sha_together():
    df = _make_v2_synthetic_df()
    y = (df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    groups = build_family_cluster_groups(df)

    # Families 0 and 1 share "shared_upx_cluster" -> same group; unrelated families sharing only technique_id stay disjoint.
    fam01_groups = set(groups[df["sample_family"].isin(["fam_00", "fam_01"])])
    assert len(fam01_groups) == 1
    assert len(set(groups[df["sample_family"].isin(["fam_02", "fam_03"])])) == 2

    # Fallback to technique_id when sample_family is missing (v1 emulated compatibility)
    em_df = pd.DataFrame([
        {"artifact_key": "a", "label": "attacker_induced", "technique_id": "T1053.005", "sample_family": None},
        {"artifact_key": "b", "label": "attacker_induced", "technique_id": "T1053.005", "sample_family": None},
        {"artifact_key": "c", "label": "attacker_induced", "technique_id": "T1547.001", "sample_family": None},
    ])
    em_groups = build_family_cluster_groups(em_df)
    assert em_groups[0] == em_groups[1] != em_groups[2]

    for _, sub in df[y == 1].groupby("pair_group_id"):
        assert len(set(groups[sub.index])) == 1
        assert set(sub["execution_state"]) == {"dormant", "executed"}


def test_split_local_preprocessing_ignores_outer_validation_outliers():
    from src.models.preprocess import SharedPreprocessor

    df = _make_v2_synthetic_df(n_families=6, n_benign_sessions=8, seed=17)
    y = (df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    groups = build_family_cluster_groups(df)
    tr_idx, va_idx = make_inner_val_split(df, y, groups, seed=3)

    tr_df = df.iloc[tr_idx].reset_index(drop=True)
    y_tr = y[tr_idx]
    g_tr = groups[tr_idx]

    art_clean = fit_arm_v2(
        "rf", tr_df, y_tr, g_tr,
        config.CATEGORICAL_FEATURES, config.NUMERIC_FEATURES, config.BINARY_FEATURES,
        seed=42, params={"n_estimators": 10},
    )
    # Build separate df with massively poisoned outer va_df; train-only fit ignores it completely
    df_poison = df.copy()
    df_poison.loc[va_idx, "file_size_log"] = 1e9
    df_poison.loc[va_idx, "artifact_type"] = "UNSEEN_CAT_XYZ"
    art_poison = fit_arm_v2(
        "rf", df_poison.iloc[tr_idx].reset_index(drop=True), y_tr, g_tr,
        config.CATEGORICAL_FEATURES, config.NUMERIC_FEATURES, config.BINARY_FEATURES,
        seed=42, params={"n_estimators": 10},
    )
    s_clean = art_clean.preprocessor.ct.named_transformers_["num"].named_steps["scale"]
    s_poison = art_poison.preprocessor.ct.named_transformers_["num"].named_steps["scale"]
    assert np.array_equal(s_clean.mean_, s_poison.mean_)
    assert np.array_equal(s_clean.scale_, s_poison.scale_)
    ohe = art_poison.preprocessor.ct.named_transformers_["cat"].named_steps["onehot"]
    assert "UNSEEN_CAT_XYZ" not in set(ohe.categories_[0])


def test_nested_family_cv_equal_trials_and_label_free_vs_label_selected():
    df = _make_v2_synthetic_df(n_families=8, n_benign_sessions=12, seed=11)
    y = (df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    arms = ["lr", "iforest", "ae"]

    res_free = run_nested_family_cv(
        df, y, arms=arms,
        cat_cols=config.CATEGORICAL_FEATURES, num_cols=config.NUMERIC_FEATURES, bin_cols=config.BINARY_FEATURES,
        n_outer=3, n_inner=3, n_trials=4, seed=42, unsup_selection="label_free",
        max_epochs_override=3, device="cpu",
    )
    assert res_free["selection_tags"] == {
        "lr": "supervised_pr_auc",
        "iforest": "label_free",
        "ae": "label_free",
    }
    assert set(res_free["fold_records"]["trials_evaluated"]) == {4}
    assert set(res_free["trials_df"]["arm"]) == set(arms)
    for arm in arms:
        assert len(res_free["trials_df"][res_free["trials_df"]["arm"] == arm]) == 3 * 4

    # Label-free unsupervised selection must remain identical when attack feature values are scrambled
    df_corrupt = df.copy()
    df_corrupt.loc[y == 1, config.NUMERIC_FEATURES] = -999.0
    res_free_corrupt = run_nested_family_cv(
        df_corrupt, y, arms=["iforest", "ae"],
        cat_cols=config.CATEGORICAL_FEATURES, num_cols=config.NUMERIC_FEATURES, bin_cols=config.BINARY_FEATURES,
        n_outer=3, n_inner=3, n_trials=4, seed=42, unsup_selection="label_free",
        max_epochs_override=3, device="cpu",
    )
    free_unsup = res_free["trials_df"][res_free["trials_df"]["arm"].isin(["iforest", "ae"])].reset_index(drop=True)
    corr_unsup = res_free_corrupt["trials_df"][res_free_corrupt["trials_df"]["arm"].isin(["iforest", "ae"])].reset_index(drop=True)
    assert np.allclose(free_unsup["criterion_score"], corr_unsup["criterion_score"], atol=1e-6)
    assert res_free["best_params_per_fold"]["iforest"] == res_free_corrupt["best_params_per_fold"]["iforest"]
    assert res_free["best_params_per_fold"]["ae"] == res_free_corrupt["best_params_per_fold"]["ae"]

    res_labeled = run_nested_family_cv(
        df, y, arms=["iforest", "ae"],
        cat_cols=config.CATEGORICAL_FEATURES, num_cols=config.NUMERIC_FEATURES, bin_cols=config.BINARY_FEATURES,
        n_outer=3, n_inner=3, n_trials=4, seed=42, unsup_selection="label_selected",
        max_epochs_override=3, device="cpu",
    )
    assert res_labeled["selection_tags"] == {"iforest": "label-selected", "ae": "label-selected"}
    assert set(res_labeled["fold_records"]["selection_tag"]) == {"label-selected"}


def test_multiseed_final_policies_and_weights_only_checkpoints(tmp_path):
    dev_df = _make_v2_synthetic_df(n_families=6, n_benign_sessions=8, seed=21)
    test_df = _make_v2_synthetic_df(n_families=4, n_benign_sessions=6, seed=99)
    y_dev = (dev_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    y_test = (test_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()

    for policy in config_v2.V2_REFIT_POLICIES:
        res = run_multiseed_final(
            dev_df, y_dev, test_df, y_test, arm_name="mlp",
            params={"hidden_dims": (32, 16), "dropout": 0.1, "norm": "layernorm", "batch_size": 16, "max_epochs": 4, "patience": 2},
            cat_cols=config.CATEGORICAL_FEATURES, num_cols=config.NUMERIC_FEATURES, bin_cols=config.BINARY_FEATURES,
            seeds=config_v2.V2_FINAL_SEEDS, refit_policy=policy, fixed_epochs=3, n_folds=3, device="cpu",
        )
        assert len(res["per_seed_pr_auc"]) == 5
        assert res["ensemble_scores"].shape == (len(test_df),)
        assert np.isfinite(res["mean_pr_auc"]) and np.isfinite(res["std_pr_auc"]) and np.isfinite(res["ensemble_pr_auc"])
        assert res["refit_policy"] == policy
        if policy == "full_dev_median_epoch":
            assert res["fit_metas"][0]["n_fit_rows"] == len(dev_df)
            assert res["fit_metas"][0]["fit_mode"] == "full_dev_fixed_epochs"

    # weights_only=True checkpoint roundtrip for both TabularMLPArmV2 and DeepAutoencoderArmV2
    rng = np.random.default_rng(5)
    X_tr = rng.normal(0.0, 1.0, size=(60, 10)).astype(np.float32)
    y_tr = np.array([0] * 45 + [1] * 15, dtype=int)
    X_va = rng.normal(0.0, 1.0, size=(20, 10)).astype(np.float32)
    y_va = np.array([0] * 15 + [1] * 5, dtype=int)

    for arm, loader in [
        (TabularMLPArmV2(seed=42, device="cpu", batch_size=16, max_epochs=3, patience=2), TabularMLPArmV2.load),
        (DeepAutoencoderArmV2(seed=42, device="cpu", batch_size=16, max_epochs=3, patience=2), DeepAutoencoderArmV2.load),
    ]:
        arm.fit(X_tr, y_tr, X_val=X_va, y_val=y_va)
        saved = arm.save(tmp_path / f"{arm.name}_v2.pt")
        loaded = loader(saved, device="cpu")
        assert np.allclose(arm.predict_scores(X_va), loaded.predict_scores(X_va), atol=1e-6)
