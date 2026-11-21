"""Metric tests on tiny hand-checked examples, and shared-preprocessor tests."""
import numpy as np
import pandas as pd
import pytest

from src import config
from src.eval import metrics as M
from src.models.preprocess import LeakageError, SharedPreprocessor, assert_no_forbidden_inputs
from src.data.features import compute_features
from tests.fixtures import synthetic_rows

# Tiny known example: ranking by score -> labels [1, 0, 1, 0, 0, 1]
Y = [0, 1, 0, 1, 1, 0]
S = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4]
# sorted by score desc -> y = [0, 1, 0, 1, 1, 0]


def test_precision_at_k_known():
    assert M.precision_at_k(Y, S, 1) == 0.0
    assert M.precision_at_k(Y, S, 2) == 0.5
    assert M.precision_at_k(Y, S, 4) == 0.5
    assert M.precision_at_k(Y, S, 5) == pytest.approx(3 / 5)
    assert M.precision_at_k(Y, S, 100) == pytest.approx(3 / 6)   # k > n -> k_eff = n


def test_recall_at_k_known():
    assert M.recall_at_k(Y, S, 1) == 0.0
    assert M.recall_at_k(Y, S, 2) == pytest.approx(1 / 3)
    assert M.recall_at_k(Y, S, 4) == pytest.approx(2 / 3)
    assert M.recall_at_k(Y, S, 5) == 1.0
    assert np.isnan(M.recall_at_k([0, 0], [1, 2], 1))


def test_ties_are_stable():
    y = [1, 0]
    s = [0.5, 0.5]
    assert M.precision_at_k(y, s, 1) == 1.0
    assert M.precision_at_k([0, 1], s, 1) == 0.0


def test_pr_auc_known():
    # AP = mean of precision at each positive: ranks 2,4,5 -> (1/2 + 2/4 + 3/5)/3
    assert M.pr_auc(Y, S) == pytest.approx((0.5 + 0.5 + 0.6) / 3)
    assert M.pr_auc([1, 1, 0], [3, 2, 1]) == 1.0
    assert np.isnan(M.pr_auc([0, 0], [1, 2]))


def test_fpr_at_recall_known():
    # positives scores: 0.8, 0.6, 0.5. recall 2/3 -> threshold 0.6; negatives >= 0.6: 0.9, 0.7 -> 2/3
    assert M.threshold_at_recall(Y, S, 2 / 3) == 0.6
    assert M.fpr_at_recall(Y, S, 2 / 3) == pytest.approx(2 / 3)
    # recall 0.9 needs all 3 positives -> threshold 0.5; negatives >= 0.5: 0.9, 0.7 -> 2/3
    assert M.fpr_at_recall(Y, S, 0.9) == pytest.approx(2 / 3)
    # restrict negatives to a "clean baseline" mask (only the 0.4 row)
    mask = [False, False, False, False, False, True]
    assert M.fpr_at_recall(Y, S, 0.9, negative_mask=mask) == 0.0


def test_threshold_at_fpr_and_recall():
    benign_val = np.arange(100, dtype=float)   # 0..99
    t = M.threshold_at_fpr(benign_val, 0.05)
    assert t == 95.0
    assert (benign_val > t).mean() <= 0.05
    assert M.recall_at_threshold([1, 1, 0], [96, 50, 99], t) == 0.5
    assert M.fpr_at_threshold([1, 1, 0, 0], [96, 50, 99, 1], t) == 0.5


def test_grouped_at_k():
    y = [1, 0, 0, 1]
    s = [0.9, 0.1, 0.9, 0.1]
    g = ["a", "a", "b", "b"]
    assert M.grouped_at_k(M.precision_at_k, y, s, g, 1) == 0.5


def test_bootstrap_deterministic():
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 200)
    s = rng.random(200) + y * 0.3
    g = np.repeat(np.arange(20), 10)
    a = M.bootstrap_by_group(M.pr_auc, y, s, g, n_boot=50, seed=1)
    b = M.bootstrap_by_group(M.pr_auc, y, s, g, n_boot=50, seed=1)
    assert a == b
    assert a["lo"] <= a["point"] <= a["hi"]


def test_accuracy_secondary():
    assert M.accuracy_at_threshold([1, 0, 1], [0.9, 0.1, 0.4], 0.5) == pytest.approx(2 / 3)


# ---------------- preprocessing ----------------
def test_leakage_guard():
    assert_no_forbidden_inputs(config.FEATURES)
    with pytest.raises(LeakageError):
        assert_no_forbidden_inputs(config.FEATURES + ["created_in_window"])
    with pytest.raises(LeakageError):
        assert_no_forbidden_inputs(config.FEATURES + ["label"])
    assert_no_forbidden_inputs(config.FEATURES + ["rule_hit_count"], allowed_extra=["rule_hit_count"])
    with pytest.raises(LeakageError):
        assert_no_forbidden_inputs(config.FEATURES + ["run_id"], allowed_extra=["run_id"])
    with pytest.raises(LeakageError):
        SharedPreprocessor(numeric=config.NUMERIC_FEATURES + ["file_age_minutes"])


def test_shared_preprocessor_fit_on_train_only(tmp_path):
    feats = compute_features(synthetic_rows(), sanitization_report=tmp_path / "s.csv")
    train, test = feats.iloc[:4], feats.iloc[4:]
    pre = SharedPreprocessor().fit(train)
    Xtr, Xte = pre.transform(train), pre.transform(test)
    assert Xtr.shape[1] == Xte.shape[1] == len(pre.feature_origin_)
    assert set(pre.feature_origin_) <= set(config.FEATURES)
    assert not np.isnan(Xtr).any() and not np.isnan(Xte).any()
    # unseen categorical level in test ("process") is ignored, not an error
    assert "process" not in set(train["artifact_type"])
    # scaler statistics come from train only
    scaler = pre.ct.named_transformers_["num"].named_steps["scale"]
    assert np.allclose(scaler.mean_[: len(config.NUMERIC_FEATURES)],
                       train[config.NUMERIC_FEATURES].fillna(0).mean().values)
    # missing indicator added for numeric columns that had NaN in train (file_entropy)
    assert pre.feature_origin_.count("file_entropy") >= 2


def test_preprocessor_numeric_only_track_b():
    df = pd.DataFrame({"a": [1.0, 2.0, np.nan], "b": [0.0, 1.0, 2.0]})
    pre = SharedPreprocessor(categorical=[], numeric=["a", "b"], binary=[]).fit(df)
    X = pre.transform(df)
    assert X.shape == (3, 3)   # a, b, missing-indicator(a)


def test_preprocessor_keeps_all_nan_numeric_column():
    df = pd.DataFrame({"a": [np.nan, np.nan, np.nan], "b": [1.0, 2.0, 3.0]})
    pre = SharedPreprocessor(categorical=[], numeric=["a", "b"], binary=[]).fit(df)
    X = pre.transform(df)
    assert X.shape[1] == len(pre.feature_origin_) == len(pre.feature_names_) == 3
