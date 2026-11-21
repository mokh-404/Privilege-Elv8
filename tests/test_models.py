"""Unit and smoke tests for all five mandatory model families + optional LR."""
import numpy as np
import pandas as pd
import pytest
from torch import nn

from src import config
from src.eval.metrics import pr_auc
from src.models.autoencoder import DeepAutoencoderArm, DeepAutoencoderNet
from src.models.mlp import TabularMLPArm, TabularMLPNet
from src.models.preprocess import SharedPreprocessor
from src.models.sklearn_models import (
    IsolationForestArm,
    RandomForestArm,
    XGBoostArm,
    build_logistic_regression_arm,
)


def _toy_data(n: int = 200, d: int = 12, seed: int = 42):
    rng = np.random.default_rng(seed)
    n_ben = n // 2
    n_att = n - n_ben
    X_b = rng.normal(0.0, 1.0, size=(n_ben, d)).astype(np.float32)
    X_a = rng.normal(2.5, 1.0, size=(n_att, d)).astype(np.float32)
    X = np.vstack([X_b, X_a])
    y = np.concatenate([np.zeros(n_ben, dtype=int), np.ones(n_att, dtype=int)])
    return X, y


def test_mlp_exact_architecture():
    net = TabularMLPNet(25)
    layers = list(net.net.children())
    assert isinstance(layers[0], nn.Linear) and (layers[0].in_features, layers[0].out_features) == (25, 128)
    assert isinstance(layers[1], nn.BatchNorm1d) and layers[1].num_features == 128
    assert isinstance(layers[2], nn.ReLU)
    assert isinstance(layers[3], nn.Dropout) and layers[3].p == pytest.approx(0.3)
    assert isinstance(layers[4], nn.Linear) and (layers[4].in_features, layers[4].out_features) == (128, 64)
    assert isinstance(layers[5], nn.BatchNorm1d) and layers[5].num_features == 64
    assert isinstance(layers[6], nn.ReLU)
    assert isinstance(layers[7], nn.Dropout) and layers[7].p == pytest.approx(0.2)
    assert isinstance(layers[8], nn.Linear) and (layers[8].in_features, layers[8].out_features) == (64, 32)
    assert isinstance(layers[9], nn.ReLU)
    assert isinstance(layers[10], nn.Linear) and (layers[10].in_features, layers[10].out_features) == (32, 1)


def test_autoencoder_exact_architecture():
    net = DeepAutoencoderNet(25)
    layers = list(net.net.children())
    dims = [(l.in_features, l.out_features) for l in layers if isinstance(l, nn.Linear)]
    assert dims == [(25, 64), (64, 32), (32, 16), (16, 32), (32, 64), (64, 25)]


def test_unsupervised_arms_never_see_attack_rows():
    X, y = _toy_data(160, 10, seed=1)
    X_val, y_val = _toy_data(80, 10, seed=2)
    X_test, _ = _toy_data(40, 10, seed=3)

    # Corrupt attack rows drastically; unsupervised arms must ignore them completely.
    X_corrupt = X.copy()
    X_corrupt[y == 1] = 1e6
    X_val_corrupt = X_val.copy()
    X_val_corrupt[y_val == 1] = -1e6

    for arm1, arm2 in [
        (IsolationForestArm(seed=42, n_estimators=20), IsolationForestArm(seed=42, n_estimators=20)),
        (DeepAutoencoderArm(seed=42, device="cpu", max_epochs=3),
         DeepAutoencoderArm(seed=42, device="cpu", max_epochs=3)),
    ]:
        arm1.fit(X, y, X_val=X_val, y_val=y_val)
        arm2.fit(X_corrupt, y, X_val=X_val_corrupt, y_val=y_val)
        assert arm1.n_attack_seen_in_fit_ == 0
        assert np.allclose(arm1.predict_scores(X_test), arm2.predict_scores(X_test), atol=1e-6)


def test_mlp_batchnorm_remainder_one_and_cpu_fallback(monkeypatch):
    monkeypatch.setenv("DFIR_FORCE_CPU", "1")
    # 65 rows with batch_size=32 -> 65 % 32 == 1 (triggers drop_last guard for BatchNorm1d)
    X, y = _toy_data(65, 8, seed=7)
    X_va, y_va = _toy_data(30, 8, seed=8)
    arm = TabularMLPArm(seed=42, batch_size=32, max_epochs=2, patience=2).fit(X, y, X_val=X_va, y_val=y_va)
    assert next(arm.net.parameters()).device.type == "cpu"
    scores = arm.predict_scores(X_va)
    assert scores.shape == (30,) and np.isfinite(scores).all()


def test_mlp_requires_caller_val_split():
    X, y = _toy_data(40, 6)
    with pytest.raises(ValueError):
        TabularMLPArm().fit(X, y)


def test_save_load_roundtrip(tmp_path):
    X, y = _toy_data(100, 8, seed=11)
    X_va, y_va = _toy_data(40, 8, seed=12)
    for arm, loader in [
        (RandomForestArm(seed=42, n_estimators=10), RandomForestArm.load),
        (XGBoostArm(seed=42, n_estimators=10), XGBoostArm.load),
        (IsolationForestArm(seed=42, n_estimators=10), IsolationForestArm.load),
        (TabularMLPArm(seed=42, device="cpu", max_epochs=2), TabularMLPArm.load),
        (DeepAutoencoderArm(seed=42, device="cpu", max_epochs=2), DeepAutoencoderArm.load),
    ]:
        arm.fit(X, y, X_val=X_va, y_val=y_va)
        p = arm.save(tmp_path / f"{arm.name}.bin")
        reloaded = loader(p)
        assert np.allclose(arm.predict_scores(X_va), reloaded.predict_scores(X_va), atol=1e-6)


def test_all_five_arms_plus_lr_1000_row_smoke():
    X_raw, y = _toy_data(1000, 12, seed=42)
    cols = [f"f{i}" for i in range(12)]
    df = pd.DataFrame(X_raw, columns=cols)
    tr_idx, va_idx, te_idx = np.arange(0, 600), np.arange(600, 800), np.arange(800, 1000)

    # Shuffle deterministically so all slices have both classes
    perm = np.random.default_rng(42).permutation(1000)
    df, y = df.iloc[perm].reset_index(drop=True), y[perm]

    pre_sup = SharedPreprocessor(categorical=[], numeric=cols, binary=[]).fit(df.iloc[tr_idx])
    pre_uns = SharedPreprocessor(categorical=[], numeric=cols, binary=[]).fit(
        df.iloc[tr_idx[y[tr_idx] == 0]]
    )

    arms = [
        RandomForestArm(seed=42, n_estimators=20),
        XGBoostArm(seed=42, n_estimators=20),
        IsolationForestArm(seed=42, n_estimators=20),
        TabularMLPArm(seed=42, device="cpu", max_epochs=4),
        DeepAutoencoderArm(seed=42, device="cpu", max_epochs=4),
        build_logistic_regression_arm(seed=42),
    ]
    for arm in arms:
        pre = pre_uns if arm.is_unsupervised else pre_sup
        arm.fit(pre.transform(df.iloc[tr_idx]), y[tr_idx], X_val=pre.transform(df.iloc[va_idx]), y_val=y[va_idx])
        s = arm.predict_scores(pre.transform(df.iloc[te_idx]))
        assert s.shape == (len(te_idx),) and np.isfinite(s).all()
        assert 0.0 <= pr_auc(y[te_idx], s) <= 1.0
