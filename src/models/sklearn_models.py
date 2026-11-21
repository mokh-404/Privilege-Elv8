"""Classical sklearn & XGBoost ranking arms (Track A and Track B).

Every arm implements a uniform ranking interface:
    fit(X_train, y_train, X_val=None, y_val=None) -> self
    predict_scores(X) -> np.ndarray   # higher = ranked as more attacker-like / anomalous
    save(path) / load(path)

IsolationForestArm is strictly unsupervised: it drops attack rows inside fit() and
records n_attack_seen_in_fit_ = 0.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

from src import config


class BaseArm:
    """Base interface for ranking models."""

    name: str = "base"
    is_unsupervised: bool = False

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "BaseArm":  # pragma: no cover
        raise NotImplementedError

    def predict_scores(self, X) -> np.ndarray:  # pragma: no cover
        raise NotImplementedError

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(cls, path: str | Path) -> "BaseArm":
        return joblib.load(path)


def _check_supervised_labels(y: np.ndarray) -> tuple[int, int]:
    y_arr = np.asarray(y).astype(int).ravel()
    n_pos = int((y_arr == 1).sum())
    n_neg = int((y_arr == 0).sum())
    if n_pos == 0 or n_neg == 0:
        raise ValueError(f"Supervised arm requires both classes in training data; got pos={n_pos}, neg={n_neg}")
    return n_pos, n_neg


class RandomForestArm(BaseArm):
    """Supervised classical tree ensemble with class_weight='balanced_subsample'."""

    name = "rf"
    is_unsupervised = False

    def __init__(self, seed: int = config.SEED, **params: Any):
        self.seed = int(seed)
        merged = dict(config.DEFAULT_PARAMS["rf"])
        merged.update(params)
        self.params = merged
        self.model: RandomForestClassifier | None = None

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "RandomForestArm":
        X_arr = np.asarray(X_train)
        y_arr = np.asarray(y_train).astype(int).ravel()
        _check_supervised_labels(y_arr)
        self.model = RandomForestClassifier(
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=self.seed,
            **self.params,
        )
        self.model.fit(X_arr, y_arr)
        return self

    def predict_scores(self, X) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("RandomForestArm must be fitted before predict_scores")
        proba = self.model.predict_proba(np.asarray(X))
        pos_idx = list(self.model.classes_).index(1)
        return proba[:, pos_idx].astype(float)


class XGBoostArm(BaseArm):
    """Supervised gradient-boosted trees with tree_method='hist' and scale_pos_weight."""

    name = "xgb"
    is_unsupervised = False

    def __init__(self, seed: int = config.SEED, **params: Any):
        self.seed = int(seed)
        merged = dict(config.DEFAULT_PARAMS["xgb"])
        merged.update(params)
        self.params = merged
        self.scale_pos_weight_: float | None = None
        self.model: XGBClassifier | None = None

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "XGBoostArm":
        X_arr = np.asarray(X_train)
        y_arr = np.asarray(y_train).astype(int).ravel()
        n_pos, n_neg = _check_supervised_labels(y_arr)
        self.scale_pos_weight_ = float(n_neg / n_pos)
        self.model = XGBClassifier(
            tree_method="hist",
            scale_pos_weight=self.scale_pos_weight_,
            eval_metric="logloss",
            n_jobs=-1,
            random_state=self.seed,
            **self.params,
        )
        self.model.fit(X_arr, y_arr)
        return self

    def predict_scores(self, X) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("XGBoostArm must be fitted before predict_scores")
        return self.model.predict_proba(np.asarray(X))[:, 1].astype(float)


class IsolationForestArm(BaseArm):
    """Unsupervised classical outlier ranker, trained strictly on benign rows (y == 0)."""

    name = "iforest"
    is_unsupervised = True

    def __init__(self, seed: int = config.SEED, **params: Any):
        self.seed = int(seed)
        merged = dict(config.DEFAULT_PARAMS["iforest"])
        merged.update(params)
        self.params = merged
        self.model: IsolationForest | None = None
        self.n_attack_seen_in_fit_: int = 0
        self.n_benign_fit_: int = 0

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "IsolationForestArm":
        X_arr = np.asarray(X_train)
        y_arr = np.asarray(y_train).astype(int).ravel()
        X_benign = X_arr[y_arr == 0]
        if len(X_benign) == 0:
            raise ValueError("IsolationForestArm requires at least one benign row (y == 0)")
        self.n_attack_seen_in_fit_ = 0
        self.n_benign_fit_ = int(len(X_benign))
        self.model = IsolationForest(
            random_state=self.seed,
            n_jobs=-1,
            **self.params,
        )
        self.model.fit(X_benign)
        return self

    def predict_scores(self, X) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("IsolationForestArm must be fitted before predict_scores")
        return (-self.model.decision_function(np.asarray(X))).astype(float)


class LogisticRegressionArm(BaseArm):
    """Optional sanity baseline (kept separate from the 5 mandatory model families)."""

    name = "lr"
    is_unsupervised = False

    def __init__(self, seed: int = config.SEED, **params: Any):
        self.seed = int(seed)
        merged = dict(config.DEFAULT_PARAMS["lr"])
        merged.update(params)
        self.params = merged
        self.model: LogisticRegression | None = None

    def fit(self, X_train, y_train, X_val=None, y_val=None) -> "LogisticRegressionArm":
        X_arr = np.asarray(X_train)
        y_arr = np.asarray(y_train).astype(int).ravel()
        _check_supervised_labels(y_arr)
        self.model = LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            random_state=self.seed,
            **self.params,
        )
        self.model.fit(X_arr, y_arr)
        return self

    def predict_scores(self, X) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("LogisticRegressionArm must be fitted before predict_scores")
        proba = self.model.predict_proba(np.asarray(X))
        pos_idx = list(self.model.classes_).index(1)
        return proba[:, pos_idx].astype(float)


def build_logistic_regression_arm(seed: int = config.SEED, **params: Any) -> LogisticRegressionArm:
    """Explicit helper for the optional logistic-regression sanity baseline (ML-06)."""
    return LogisticRegressionArm(seed=seed, **params)
